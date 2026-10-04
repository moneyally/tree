            .client
            .app_data(&format!("media/consumed/{}", hex::encode(attachment_id)))?
            .is_some())
    }

    pub fn send_text(&self, gid: &[u8], text: &str) -> Result<String, Error> {
        let roster = self.roster(gid)?;
        let recipients: Vec<String> = roster
            .values()
            .filter(|device| device.as_str() != self.device_id())
            .cloned()
            .collect();
        if recipients.is_empty() {
            return Err(Error::Usage("group has no other devices".into()));
        }
        let (message_id, body) = self.with_group(gid, |group| {
            group.send_message(&self.client, text.as_bytes())
        })?;
        let reply = self
            .api
            .send(&self.creds, &recipients, &body, Some(message_id.as_bytes()))?;
        let id = reply.body["id"]
            .as_str()
            .or_else(|| reply.body["message_id"].as_str())
            .unwrap_or_default();
        if id.is_empty() {
            return Err(Error::Usage("server did not return a message id".into()));
        }
        Ok(id.to_string())
    }

    /// Fetches mailbox messages, routes envelopes to the correct local group,
    /// joins Welcome messages, and acknowledges only messages that have been