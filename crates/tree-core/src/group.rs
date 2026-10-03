        }
        me.provider.atomically(|| {
            self.mls
                .clear_pending_commit(me.provider.storage())
                .map_err(group_err)?;
            self.state.pending = None;
            self.save(me)
        })
    }

    fn begin_commit<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        build: impl FnOnce(&mut MlsGroup) -> Result<(MlsMessageOut, Option<MlsMessageOut>), TreeError>,
    ) -> Result<PendingCommit, TreeError> {
        if !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        // (OpenMLS's own pending commit is always stored together with ours.)
        if self.state.pending.is_some() {
            return Err(TreeError::CommitPending);
        }
        let epoch = self.epoch();
        me.provider.atomically(|| {
            // Tree never stores proposals (F-007); make sure none can be
            // folded into this commit.
            self.mls
                .clear_pending_proposals(me.provider.storage())
                .map_err(group_err)?;
            let result = build(&mut self.mls).and_then(|(commit, welcome)| {
                // Sealed with the CURRENT epoch: what the other members hold.
                let commit = self.seal(me, &commit.to_bytes().map_err(group_err)?)?;
                let welcome = welcome
                    .map(|w| w.to_bytes().map_err(group_err))
                    .transpose()?;
                self.state.pending = Some(Pending {
                    epoch,
                    commit,
                    welcome,
                });
                self.save(me)
            });
            if result.is_err() {
                self.state.pending = None;
                let _ = self.mls.clear_pending_commit(me.provider.storage());
            }
            result
        })?;
        Ok(self.pending_commit().expect("pending commit just stored"))
    }

    // ----- application messages ---------------------------------------------

    fn send_control<P: TreeProvider>(
        &mut self,
        me: &Client<P>,
        control: Control,
    ) -> Result<Vec<u8>, TreeError> {
        if !self.is_admin(me) || !self.mls.is_active() {
            return Err(TreeError::NotAMember);
        }
        let old_seq = self.state.last_control_seq;
        let old_author = self.state.last_control_author;
        let seq = old_seq
            .checked_add(1)
            .ok_or_else(|| TreeError::Group("settings sequence exhausted".into()))?;
        let bytes = encode_control(seq, &control)?;
        let result = me.provider.atomically(|| {
            let out = self
                .mls
                .create_message(&me.provider, &me.signer, &bytes)
                .map_err(group_err)?;