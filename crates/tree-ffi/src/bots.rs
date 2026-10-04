//! Bots for the apps (Wave 5, PROTOCOL.md 8.16): the bot factory, the bot
//! label, inline buttons. Only type conversions; the behaviour is in
//! `tree_client::bots`.

use tree_client::{BotCommand, BotInfo, Button, OwnedBot};

use crate::{unhex, Commit, TreeSession, R};

/// A command a bot lists (`/command`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct BotCommandInfo {
    pub command: String,
    pub description: String,
}

/// What anyone may know about a bot.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Bot {
    pub account: String,
    pub username: String,
    pub description: String,
    pub commands: Vec<BotCommandInfo>,
    /// `bot.privacy_mode`: in groups it gets only what is addressed to it.
    pub privacy_mode: bool,
    pub join_groups: bool,
    pub inline: bool,
    pub directory: bool,
}

impl From<BotInfo> for Bot {
    fn from(b: BotInfo) -> Self {
        Bot {
            account: b.account,
            username: b.username,
            description: b.description,
            commands: b.commands.into_iter().map(|c| BotCommandInfo { command: c.command, description: c.description }).collect(),
            privacy_mode: b.privacy_mode,
            join_groups: b.join_groups,
            inline: b.inline,
            directory: b.directory,
        }
    }
}

/// One bot feature on the owner's screen; `locked`: why it can never be
/// applied (bot payments and tips).
#[derive(Debug, Clone, uniffi::Record)]
pub struct BotFeatureInfo {
    pub key: String,
    pub applied: bool,
    pub locked: Option<String>,
}

/// A bot as its owner sees it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MyBot {
    pub bot: Bot,
    pub token_active: bool,
    pub gateway_devices: u32,
    pub contacts: u32,
    pub reports_open: u32,
    pub features: Vec<BotFeatureInfo>,
}

impl From<OwnedBot> for MyBot {
    fn from(b: OwnedBot) -> Self {
        MyBot {
            bot: b.info.into(),
            token_active: b.token_active,
            gateway_devices: b.gateway_devices,
            contacts: b.contacts,
            reports_open: b.reports_open,
            features: b.features.into_iter().map(|f| BotFeatureInfo { key: f.key, applied: f.applied, locked: f.locked }).collect(),
        }
    }
}

/// A new bot and its token: shown once, then only the gateway has it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct NewBot {
    pub bot: MyBot,
    pub token: String,
}

/// An inline button under a bot's message.
#[derive(Debug, Clone, uniffi::Record)]
pub struct BotButton {
    pub text: String,
    pub data: String,
}

pub(crate) fn rows(kb: Vec<Vec<Button>>) -> Vec<Vec<BotButton>> {
    kb.into_iter().map(|r| r.into_iter().map(|b| BotButton { text: b.text, data: b.data }).collect()).collect()
}

#[uniffi::export]
impl TreeSession {
    // --- the bot factory (owners) ---

    /// Creates a bot (the same proof of work as a signup, `pow_bits` as the
    /// server requires). The token is in the answer only this once.
    pub fn create_bot(&self, username: String, pow_bits: u32) -> R<NewBot> {
        let (b, token) = self.s().create_bot(&username, pow_bits)?;
        Ok(NewBot { bot: b.into(), token })
    }

    pub fn my_bots(&self) -> R<Vec<MyBot>> {
        Ok(self.s().my_bots()?.into_iter().map(Into::into).collect())
    }

    pub fn set_bot_profile(&self, account: String, description: Option<String>, commands: Option<Vec<BotCommandInfo>>) -> R<MyBot> {
        let commands: Option<Vec<BotCommand>> = commands.map(|v| v.into_iter().map(|c| BotCommand { command: c.command, description: c.description }).collect());
        Ok(self.s().set_bot_profile(&account, description.as_deref(), commands.as_deref())?.into())
    }

    /// `bot.privacy_mode`, `bot.join_groups`, `bot.inline`, `bot.directory`;
    /// `bot.payments` and `bot.tips` are refused (`RELEASED_ALWAYS`).
    pub fn set_bot_feature(&self, account: String, key: String, apply: bool) -> R<MyBot> {
        Ok(self.s().set_bot_feature(&account, &key, apply)?.into())
    }

    /// A new token (shown once); the old one and its gateway device stop now.
    pub fn rotate_bot_token(&self, account: String) -> R<String> {
        Ok(self.s().rotate_bot_token(&account)?)
    }

    pub fn revoke_bot_token(&self, account: String) -> R<MyBot> {
        Ok(self.s().revoke_bot_token(&account)?.into())
    }

    pub fn delete_bot(&self, account: String) -> R<()> {
        Ok(self.s().delete_bot(&account)?)
    }

    // --- bots for everyone ---

    pub fn bot_directory(&self, query: String) -> R<Vec<Bot>> {
        Ok(self.s().bot_directory(&query)?.into_iter().map(Into::into).collect())
    }

    pub fn find_bot(&self, username: String) -> R<Option<Bot>> {
        Ok(self.s().find_bot(&username)?.map(Into::into))
    }

    /// Whether an account is a bot, as the server says (cached briefly).
    pub fn bot_info(&self, account: String) -> R<Option<Bot>> {
        Ok(self.s().bot_info(&account)?.map(Into::into))
    }

    /// Adds a bot (account id or @username) to a chat; refused while the
    /// chat releases `chat.bots`.
    pub fn add_bot(&self, group: String, who: String) -> R<Commit> {
        Ok(self.s().add_bot(&unhex(&group, "group")?, &who)?.0.into())
    }

    /// Blocks a bot: its messages are dropped, and it can no longer reach
    /// this account.
    pub fn block_bot(&self, account: String) -> R<()> {
        Ok(self.s().block_bot(&account)?)
    }

    /// Asks the server about the chat's bots now (labels, settings).
    pub fn refresh_bots(&self, group: String) -> R<()> {
        Ok(self.s().refresh_bots(&unhex(&group, "group")?)?)
    }

    /// The buttons under a bot's message.
    pub fn buttons(&self, group: String, id: String) -> R<Vec<Vec<BotButton>>> {
        Ok(rows(self.s().buttons(&unhex(&group, "group")?, &id)?))
    }

    /// Presses a button: only that bot gets it. Returns the press id; the
    /// bot's answer comes as `CallbackAnswer`.
    pub fn press_button(&self, group: String, id: String, data: String) -> R<String> {
        Ok(self.s().press_button(&unhex(&group, "group")?, &id, &data)?)
    }

    // --- a bot's own device (what the gateway does; for tests and tools) ---

    /// A bot's device sends a text with buttons.
    pub fn send_buttons(&self, group: String, text: String, buttons: Vec<Vec<BotButton>>, reply_to: Option<String>) -> R<String> {
        let kb = buttons.into_iter().map(|r| r.into_iter().map(|b| Button { text: b.text, data: b.data }).collect()).collect();
        Ok(self.s().send_buttons(&unhex(&group, "group")?, &text, kb, reply_to.as_deref())?)
    }

    /// A bot's device answers a press (`CallbackQuery`).
    pub fn answer_callback(&self, group: String, id: String, text: Option<String>, alert: bool) -> R<()> {
        Ok(self.s().answer_callback(&unhex(&group, "group")?, &id, text.as_deref(), alert)?)
    }
}

#[uniffi::export]
impl TreeSession {
    /// A bot's device in a new profile, registered with the bot token
    /// (normally the gateway does this, docs/BOT_GATEWAY.md).
    #[uniffi::constructor]
    pub fn create_bot_device(path: String, passphrase: String, server: String, token: String) -> R<std::sync::Arc<Self>> {
        Ok(Self::wrap(tree_client::Session::create_bot_device(&path, &passphrase, &server, &token)?))
    }
}
