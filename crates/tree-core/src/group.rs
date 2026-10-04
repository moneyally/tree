
    /// Encrypts a chat message for everyone in the group (in the current
    /// epoch; also while a commit of ours is pending).
    pub fn send<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        body: &[u8],
    ) -> Result<Vec<u8>, TreeError> {
        if !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        if body.starts_with(CONTROL_MAGIC) {
            return Err(TreeError::Rejected(
                "message body uses a reserved Tree control prefix".into(),
            ));
        }
        self.atomic(me, |this| {
            let out = this
                .mls
                .create_message(&me.provider, &me.signer, body)
                .map_err(group_err)?;
            this.seal(me, &out.to_bytes().map_err(group_err)?)
        })
    }

    // ----- receiving ---------------------------------------------------------

    /// Reprocesses future-epoch envelopes after their epoch becomes available.
    ///
    /// Envelopes that are still ahead of the current epoch remain queued.
    /// Envelopes that now authenticate are processed through the normal receive
    /// path, so replay/authorization/MLS validation is not bypassed. An item
    /// that becomes permanently invalid is removed from the retry queue.
    pub fn retry_held<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
    ) -> Result<Vec<Incoming>, TreeError> {
        if !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }

        let now = unix_now();
        self.state.prune_future(now);

        let mut ready = self
            .state
            .future
            .iter()
            .filter(|pending| pending.epoch <= self.epoch())
            .map(|pending| (pending.epoch, pending.received_at, pending.bytes.clone()))
            .collect::<Vec<_>>();
        ready.sort_by_key(|(epoch, received_at, _)| (*epoch, *received_at));

        let mut results = Vec::new();
        for (_, _, bytes) in ready {
            let hash = sha256(&bytes);
            match self.receive(me, &bytes) {
                Ok(Incoming::HeldForRetry { .. }) => {
                    // The epoch advanced again while processing. Keep it queued.
                }
                Ok(incoming) => results.push(incoming),
                Err(_) => {
                    // This envelope was only admitted to the queue from an
                    // unauthenticated future-epoch peek. Once its epoch is
                    // available, a failed full authentication is permanent for
                    // this byte string; remove it so a bad entry cannot poison
                    // retries forever.
                    self.state.future.retain(|pending| sha256(&pending.bytes) != hash);
                    self.save(me)?;
                }
            }
        }
        Ok(results)
    }

    /// Decrypts and authenticates anything received for this group
    /// (PROTOCOL.md section 6.6). Anything tampered with, replayed, from a
    /// non-member, for another group, a proposal, or a commit for a past
    /// epoch is rejected.
    pub fn receive<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        bytes: &[u8],
    ) -> Result<Incoming, TreeError> {
        if !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        let hash = sha256(bytes);
        if let Some(p) = &self.state.pending {
            if bool::from(sha256(&p.commit).ct_eq(&hash)) {
                // The server only delivers accepted commits: ours won.
                let epoch = self.confirm_commit(me)?;
                return Ok(Incoming::OwnCommitMerged { epoch });
            }
        }
        if self
            .state
            .sent
            .iter()
            .any(|(_, h)| bool::from(h.ct_eq(&hash)))
        {
            return Ok(Incoming::OwnEcho);
        }
        if let Some((epoch, _)) = self
            .state
            .processed
            .iter()
            .find(|(_, h)| bool::from(h.ct_eq(&hash)))
        {
            if *epoch < self.epoch() {
                return Err(TreeError::Rejected("past epoch".into()));
            }
            return Ok(Incoming::NoOp);
        }
        let now = unix_now();

        // Authenticate the outer envelope before trusting any MLS header.
        // Current and retained past keys are the only keys available here. A
        // genuine future-epoch envelope cannot be authenticated yet, so only
        // a seal mismatch is eligible for the untrusted epoch peek below.
        let (epoch, body) = match self.open_envelope(me, bytes) {
            Ok(opened) => opened,
            Err(err) if matches!(&err, TreeError::Rejected(reason) if reason == "envelope seal mismatch") =>
            {
                if bytes.len() == 1 + Self::TAG_LEN {
                    return Err(err);
                }
                let announced = peek_epoch(bytes, self.mls.group_id().as_slice())?;
                if announced <= self.epoch() {
                    return Err(err);
                }
                return self.atomic(me, |this| {
                    this.state.prune_future(now);
                    if !this
                        .state
                        .future
                        .iter()
                        .any(|p| bool::from(sha256(&p.bytes).ct_eq(&hash)))
                    {
                        this.state.future.push(PendingEnvelope {
                            epoch: announced,
                            received_at: now,
                            bytes: bytes.to_vec(),
                        });
                        this.state.prune_future(now);
                        this.save(me)?;
                    }
                    Ok(Incoming::HeldForRetry { epoch: announced })
                });
            }
            Err(err) => return Err(err),
        };
        self.atomic(me, |this| {
            let msg = MlsMessageIn::tls_deserialize_exact(body)
                .map_err(|e| TreeError::Malformed(format!("{e:?}")))?;
            let protocol = msg
                .try_into_protocol_message()
                .map_err(|_| TreeError::Malformed("not a group message".into()))?;
            if protocol.wire_format() != WireFormat::PrivateMessage {
                return Err(TreeError::Rejected(
                    "only private messages are accepted".into(),
                ));
            }
            if protocol.group_id().as_slice() != this.mls.group_id().as_slice()
                || protocol.epoch().as_u64() != epoch
            {
                return Err(TreeError::Rejected(
                    "header does not match the envelope".into(),
                ));
            }
            match protocol.content_type() {
                ContentType::Application => {}
                ContentType::Commit if epoch == this.epoch() => {}
                ContentType::Commit => {
                    return Err(TreeError::Rejected("commit for a past epoch".into()))
                }
                ContentType::Proposal => {
                    return Err(TreeError::Rejected(
                        "proposals are not accepted in Tree v1 (F-007)".into(),
                    ))
                }
            }
            this.process(me, protocol, epoch, hash)
        })
    }

    fn process<P: TreeProvider>(
        &mut self,
        me: &Client<P>,