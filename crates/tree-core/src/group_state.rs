        assert!(GroupState::decode(&long).is_err(), "trailing byte");

        let mut v = enc.clone();
        v[0] = 7;
        assert!(GroupState::decode(&v).is_err(), "version");
    }

    #[test]
    fn legacy_v5_decodes_without_message_ledger() {
        let encoded = sample().encode().unwrap();
        let msg_len = encoded.len();
        let mut v5 = encoded;
        // Strip the v7/v8 control-author/tag/message-ledger suffix.
        let suffix_len = 1 + 32 // v7 global control author
            + 1 + 8 + 32 // v8 title tag
            + 1 + 8 + 32 // v8 disappearing tag
            + 2 + (32 + 8 + 32) // v8 one admin tag
            + 4 + sample().messages.encode().unwrap().len(); // ledger length + bytes
        v5.truncate(msg_len - suffix_len);
        v5[0] = 5;