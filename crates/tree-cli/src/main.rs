use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tree_core::{Client, Incoming, RecoveryPhrase, StoredProvider};

const AUTH_CONTEXT: &str = "tree-auth-v1";

#[derive(Parser, Debug)]
#[command(name = "tree", about = "Tree end-to-end encrypted messenger CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new encrypted local profile.
    Init(InitArgs),
    /// Register the profile as a new Tree account.
    Signup(SignupArgs),
    /// Upload fresh one-time MLS key packages.
    UploadKeys(UploadKeysArgs),
    /// Print local/server identity information.
    Info(ProfileArgs),
    /// Generate and persist a 24-word recovery phrase locally.
    RecoveryGenerate(ProfileArgs),
    /// Register the stored recovery public key with the server.
    RecoverySetup(NetworkArgs),
    /// Recover an account into a fresh local profile.
    Recovery(RecoverArgs),
    /// Create a new local MLS group.
    CreateGroup(ProfileArgs),
    /// Add every available device of an account to a group.
    Invite(InviteArgs),
    /// Encrypt and send one application message.
    Send(SendArgs),
    /// Fetch mailbox entries, decrypt them, and acknowledge successful processing.
    Receive(ReceiveArgs),
}

#[derive(Args, Debug)]
struct ProfileArgs {
    /// Base path of the encrypted profile database, for example ./alice.db.
    #[arg(long)]
    profile: PathBuf,
    /// Password protecting the local profile.
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct NetworkArgs {
    #[arg(long)]
    profile: PathBuf,
    /// Tree server base URL, for example https://example.com.
    #[arg(long)]
    server: String,
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct SignupArgs {
    #[arg(long)]
    profile: PathBuf,
    /// Tree server base URL, for example https://example.com.
    #[arg(long)]
    server: String,
    /// Signup proof-of-work difficulty. Must match the server's POW_BITS.
    #[arg(long, default_value_t = 20)]
    pow_bits: u32,
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct InitArgs {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct RecoverArgs {
    #[arg(long)]
    server: String,
    #[arg(long)]
    account: String,
    /// Leave empty to enter the phrase without putting it in shell history.
    #[arg(long)]
    phrase: Option<String>,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct UploadKeysArgs {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    server: String,
    #[arg(long, default_value_t = 10)]
    count: usize,
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct InviteArgs {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    server: String,
    #[arg(long)]
    group: String,
    #[arg(long)]
    account: String,
    /// Existing group device ids that must receive the commit.
    /// Omit this when the group has only the creator.
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct SendArgs {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    server: String,
    #[arg(long)]
    group: String,
    /// One or more recipient device ids.
    #[arg(long, value_delimiter = ',')]
    recipients: Vec<String>,
    #[arg(long)]
    message: String,
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct ReceiveArgs {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    server: String,
    /// Long-poll timeout. 0 fetches immediately.
    #[arg(long, default_value_t = 10)]
    wait: u64,
    #[arg(long)]
    passphrase: Option<String>,
}

struct Api {
    http: reqwest::Client,
    base: String,
}

impl Api {
    fn new(server: &str) -> Result<Self> {
        let base = server.trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            bail!("server must start with http:// or https://");
        }
        Ok(Self {
            http: reqwest::Client::new(),
            base,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn signed(
        &self,
        client: &Client<StoredProvider>,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        let seed = client
            .server_auth_seed()?
            .ok_or_else(|| anyhow!("profile is not registered; run signup first"))?;
        let device = client
            .server_account()?
            .ok_or_else(|| anyhow!("profile is missing server account metadata"))?
            .1;
        let key = SigningKey::from_bytes(&seed);
        let bytes = body
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .context("serialize JSON body")?
            .unwrap_or_default();
        let ts = now_secs();
        let nonce = random_hex::<16>();
        let signature = signing_message(
            method.as_str(),
            path,
            &ts.to_string(),
            &nonce,
            &device,
            &bytes,
        );
        let sig = STANDARD.encode(key.sign(&signature).to_bytes());

        let mut req = self
            .http
            .request(method, self.url(path))
            .header("X-Tree-Device", &device)
            .header("X-Tree-Timestamp", ts.to_string())
            .header("X-Tree-Nonce", &nonce)
            .header("X-Tree-Signature", sig);
        if !bytes.is_empty() {
            req = req.header("Content-Type", "application/json").body(bytes);
        }

        let resp = req.send().await.context("send HTTP request")?;
        decode(resp).await
    }

    async fn group_devices(
        &self,
        client: &Client<StoredProvider>,
        group_id: &[u8],
    ) -> Result<Vec<String>> {
        let path = format!("/v1/groups/{}/devices", hex::encode(group_id));
        let (status, body) = self.signed(client, Method::GET, &path, None).await?;
        if !status.is_success() {
            bail!("group roster failed ({status}): {body}");
        }
        body.get("devices")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("group roster response has no devices"))
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
    }

    async fn recover(
        &self,
        account_id: &str,
        phrase: &RecoveryPhrase,
        new_auth_seed: [u8; 32],
    ) -> Result<(String, String)> {
        let auth_key = SigningKey::from_bytes(&new_auth_seed);
        let recovery_key = phrase.recovery_signing_key();
        let timestamp = now_secs();
        let nonce = random_hex::<16>();
        let new_auth_pub = auth_key.verifying_key().to_bytes();
        let proof_msg = format!("tree-recovery-v1\n{account_id}\n{timestamp}\n{nonce}\n");
        let mut proof_msg = proof_msg.into_bytes();
        proof_msg.extend_from_slice(&new_auth_pub);

        let body = json!({
            "account_id": account_id,
            "recovery_pub": STANDARD.encode(recovery_key.verifying_key().to_bytes()),
            "new_auth_pub": STANDARD.encode(new_auth_pub),
            "timestamp": timestamp,
            "nonce": nonce,
            "proof": STANDARD.encode(recovery_key.sign(&proof_msg).to_bytes())
        });
        let bytes = serde_json::to_vec(&body)?;
        let resp = self
            .http
            .post(self.url("/v1/recovery"))
            .header("Content-Type", "application/json")
            .body(bytes)
            .send()
            .await
            .context("recovery request")?;
        let (status, v) = decode(resp).await?;
        if status != StatusCode::CREATED {
            bail!("recovery failed ({status}): {v}");
        }
        Ok((
            required_string(&v, "account_id")?,
            required_string(&v, "device_id")?,
        ))
    }

    async fn signup(&self, seed: [u8; 32], pow_bits: u32) -> Result<(String, String)> {
        let key = SigningKey::from_bytes(&seed);
        let pubkey = key.verifying_key().to_bytes();
        let nonce = solve_pow(&pubkey, pow_bits);

        let body = json!({
            "auth_pub": STANDARD.encode(pubkey),
            "pow_nonce": nonce
        });
        let bytes = serde_json::to_vec(&body)?;
        let ts = now_secs();
        let request_nonce = random_hex::<16>();
        let message = signing_message(
            Method::POST.as_str(),
            "/v1/accounts",
            &ts.to_string(),
            &request_nonce,
            "",
            &bytes,
        );
        let sig = STANDARD.encode(key.sign(&message).to_bytes());
        let response = self
            .http
            .post(self.url("/v1/accounts"))
            .header("X-Tree-Timestamp", ts.to_string())
            .header("X-Tree-Nonce", request_nonce)
            .header("X-Tree-Signature", sig)
            .header("Content-Type", "application/json")
            .body(bytes)
            .send()
            .await
            .context("signup request")?;

        let (status, v) = decode(response).await?;
        if status != StatusCode::CREATED {
            bail!("signup failed ({status}): {v}");
        }
        Ok((
            required_string(&v, "account_id")?,
            required_string(&v, "device_id")?,
        ))
    }
}

async fn decode(resp: reqwest::Response) -> Result<(StatusCode, Value)> {
    let status = resp.status();
    let text = resp.text().await.context("read HTTP response")?;
    if text.is_empty() {
        Ok((status, Value::Null))
    } else {
        let value = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text.clone()));
        Ok((status, value))
    }
}

fn required_string(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("server response missing {key}"))
}

fn signing_message(
    method: &str,
    path_and_query: &str,
    timestamp: &str,
    nonce: &str,
    device_id: &str,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = hex::encode(Sha256::digest(body));
    format!(
        "{AUTH_CONTEXT}\n{method}\n{path_and_query}\n{timestamp}\n{nonce}\n{device_id}\n{body_hash}"
    )
    .into_bytes()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

fn random_hex<const N: usize>() -> String {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("OS randomness unavailable");
    hex::encode(bytes)
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS randomness unavailable");
    seed
}

fn solve_pow(pubkey: &[u8; 32], bits: u32) -> u64 {
    for nonce in 0u64.. {
        let mut h = Sha256::new();
        h.update(b"tree-signup-v1");
        h.update(pubkey);
        h.update(nonce.to_be_bytes());
        if leading_zero_bits(&h.finalize()) >= bits {
            return nonce;
        }
    }
    unreachable!("u64 nonce space exhausted")
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0;
    for &b in hash {
        if b == 0 {
            count += 8;
        } else {
            return count + b.leading_zeros();
        }
    }
    count
}

fn passphrase(arg: &Option<String>) -> Result<String> {
    match arg {
        Some(v) if !v.is_empty() => Ok(v.clone()),
        Some(_) => bail!("passphrase must not be empty"),
        None => Ok(rpassword::prompt_password("Profile passphrase: ")?),
    }
}

fn open_profile(path: &Path, pass: &Option<String>) -> Result<Client<StoredProvider>> {
    let password = passphrase(pass)?;
    Client::open(path, &password).map_err(|e| anyhow!("open profile: {e}"))
}

fn group_id_from_hex(s: &str) -> Result<Vec<u8>> {
    let id = hex::decode(s).context("group must be lowercase/uppercase hex")?;
    if id.is_empty() {
        bail!("group id is empty");
    }
    Ok(id)
}

fn envelope_group_id(bytes: &[u8]) -> Result<Vec<u8>> {
    // v1 envelope: version(1) + tag(32) + MLS protocol/wire(4) +
    // group-id-len(1) + group-id + epoch(8) + content-type(1).
    if bytes.len() < 38 || bytes[0] != 1 {
        bail!("malformed Tree envelope");
    }
    let group_len = bytes[37] as usize;
    let start = 38usize;
    let end = start
        .checked_add(group_len)
        .ok_or_else(|| anyhow!("group id length overflow"))?;
    if end + 9 > bytes.len() {
        bail!("malformed Tree envelope group id");
    }
    Ok(bytes[start..end].to_vec())
}

async fn init(args: InitArgs) -> Result<()> {
    let password = passphrase(&args.passphrase)?;
    let client = Client::create(&args.profile, &password, &args.name)
        .map_err(|e| anyhow!("create profile: {e}"))?;
    println!("profile={}", args.profile.display());
    println!("name={}", client.name());
    println!("ciphersuite={:?}", client.ciphersuite());
    Ok(())
}

async fn signup(args: SignupArgs) -> Result<()> {
    let client = open_profile(&args.profile, &args.passphrase)?;
    if client.server_account()?.is_some() {
        bail!("profile is already registered");
    }

    let seed = client.server_auth_seed()?.unwrap_or_else(random_seed);
    // Persist the auth key before the network call. It is encrypted by the
    // profile database, so a failed/retried signup does not lose the key.
    client.set_server_auth_seed(&seed)?;

    let api = Api::new(&args.server)?;
    let (account_id, device_id) = api.signup(seed, args.pow_bits).await?;
    client.set_server_account(&account_id, &device_id)?;

    println!("account_id={account_id}");
    println!("device_id={device_id}");
    Ok(())
}

async fn upload_keys(args: UploadKeysArgs) -> Result<()> {
    if args.count == 0 {
        bail!("count must be positive");
    }
    let client = open_profile(&args.profile, &args.passphrase)?;
    let api = Api::new(&args.server)?;
    let mut packages = Vec::with_capacity(args.count);
    for _ in 0..args.count {
        packages.push(
            client
                .key_package()
                .map_err(|e| anyhow!("create key package: {e}"))?,
        );
    }
    let (status, body) = api
        .signed(
            &client,
            Method::POST,
            "/v1/keypackages",
            Some(json!({
                "key_packages": packages.iter().map(|p| STANDARD.encode(p)).collect::<Vec<_>>()
            })),
        )
        .await?;
    if !status.is_success() {
        bail!("key package upload failed ({status}): {body}");
    }
    println!(
        "uploaded={} server_count={}",
        body.get("stored").and_then(Value::as_u64).unwrap_or(0),
        body.get("count").and_then(Value::as_i64).unwrap_or(-1)
    );
    Ok(())
}

async fn recovery_generate(args: ProfileArgs) -> Result<()> {
    let client = open_profile(&args.profile, &args.passphrase)?;
    if client.recovery_phrase()?.is_some() {
        bail!("profile already has a recovery phrase");
    }
    let phrase =
        RecoveryPhrase::generate().map_err(|e| anyhow!("generate recovery phrase: {e}"))?;
    client
        .set_recovery_phrase(&phrase)
        .map_err(|e| anyhow!("store recovery phrase: {e}"))?;
    println!("recovery_phrase={}", phrase.phrase());
    println!("warning=store this phrase offline; it is not sent to the server");
    Ok(())
}

async fn recovery_setup(args: NetworkArgs) -> Result<()> {
    let client = open_profile(&args.profile, &args.passphrase)?;
    let phrase = client
        .recovery_phrase()?
        .ok_or_else(|| anyhow!("profile has no recovery phrase; run recovery-generate first"))?;
    let api = Api::new(&args.server)?;
    let (status, body) = api
        .signed(
            &client,
            Method::POST,
            "/v1/recovery/setup",
            Some(json!({
                "recovery_pub": STANDARD.encode(phrase.recovery_public_key())
            })),
        )
        .await?;
    if !status.is_success() {
        bail!("recovery setup failed ({status}): {body}");
    }
    println!(
        "recovery_pub={}",
        body["recovery_pub"].as_str().unwrap_or_default()
    );
    Ok(())
}

async fn recovery(args: RecoverArgs) -> Result<()> {
    check_account_id(&args.account)?;
    let phrase_text = match args.phrase {
        Some(phrase) => phrase,
        None => rpassword::prompt_password("Recovery phrase: ")?,
    };
    let phrase = RecoveryPhrase::from_phrase(&phrase_text)
        .map_err(|e| anyhow!("invalid recovery phrase: {e}"))?;
    let password = passphrase(&args.passphrase)?;
    let client = Client::create(&args.profile, &password, &args.name)
        .map_err(|e| anyhow!("create recovered profile: {e}"))?;
    client
        .set_recovery_phrase(&phrase)
        .map_err(|e| anyhow!("store recovery phrase: {e}"))?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).context("generate new authentication key")?;
    let api = Api::new(&args.server)?;
    let (account_id, device_id) = api.recover(&args.account, &phrase, seed).await?;
    if account_id != args.account {
        bail!("server returned a different account");
    }
    client.set_server_auth_seed(&seed)?;
    client.set_server_account(&account_id, &device_id)?;
    println!("account_id={account_id}");
    println!("device_id={device_id}");
    println!("warning=new device created; existing MLS groups must be re-added");
    Ok(())
}

fn check_account_id(id: &str) -> Result<()> {
    if id.len() != 22
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("account id is not a valid 16-byte base64url identifier");
    }
    Ok(())
}

async fn info(args: ProfileArgs) -> Result<()> {
    let client = open_profile(&args.profile, &args.passphrase)?;
    println!("name={}", client.name());
    println!("ciphersuite={:?}", client.ciphersuite());
    println!("member_id={}", client.member_id());
    match client.server_account()? {
        Some((account, device)) => {
            println!("account_id={account}");
            println!("device_id={device}");
        }
        None => println!("server_account=not-registered"),
    }
    println!("groups={}", client.group_ids()?.len());
    Ok(())
}

async fn create_group(args: ProfileArgs) -> Result<()> {
    let client = open_profile(&args.profile, &args.passphrase)?;
    let group = client
        .create_group()
        .map_err(|e| anyhow!("create group: {e}"))?;
    println!("group_id={}", hex::encode(group.id()));
    println!("epoch={}", group.epoch());
    Ok(())
}

fn group_member_device_id(client: &Client<StoredProvider>) -> String {
    client
        .server_account()
        .expect("profile server metadata readable")
        .expect("profile is registered")
        .1
}

async fn invite(args: InviteArgs) -> Result<()> {
    if args.account.is_empty() {
        bail!("account must not be empty");
    }
    let client = open_profile(&args.profile, &args.passphrase)?;
    let api = Api::new(&args.server)?;
    let mut group = client
        .load_group(&group_id_from_hex(&args.group)?)
        .map_err(|e| anyhow!("load group: {e}"))?;

    let (status, response) = api
        .signed(
            &client,
            Method::POST,
            "/v1/keypackages/claim",
            Some(json!({ "account_id": args.account })),
        )
        .await?;
    if !status.is_success() {
        bail!("claim failed ({status}): {response}");
    }
    let claims = response
        .get("key_packages")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("claim response has no key_packages"))?;
    if claims.is_empty() {
        bail!("target account has no available key package");
    }

    let mut transport_added = Vec::with_capacity(claims.len());
    let mut packages = Vec::with_capacity(claims.len());
    for item in claims {
        transport_added.push(required_string(item, "device_id")?);
        packages.push(
            STANDARD
                .decode(required_string(item, "key_package")?)
                .context("decode claimed key package")?,
        );
    }

    let mut recipients = args.recipients;
    if recipients.is_empty() && group.epoch() > 0 {
        recipients = api.group_devices(&client, &group.id()).await?;
        let own_device = group_member_device_id(&client);
        recipients.retain(|id| id != &own_device);
    }

    let pending = group
        .add(&client, &packages)
        .map_err(|e| anyhow!("build invite commit: {e}"))?;
    let welcome = pending
        .welcome
        .clone()
        .ok_or_else(|| anyhow!("invite did not produce a welcome"))?;

    let body = json!({
        "group_id": STANDARD.encode(&pending.group_id),
        "epoch": pending.epoch,
        "recipients": recipients,
        "body": STANDARD.encode(&pending.commit),
        "added": transport_added,
        "welcome": STANDARD.encode(welcome),
        "removed": []
    });
    let (status, response) = api
        .signed(&client, Method::POST, "/v1/commits", Some(body))
        .await?;
    if status != StatusCode::OK {
        group.discard_commit(&client).ok();
        bail!("commit rejected ({status}): {response}");
    }

    let accepted = response
        .get("accepted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !accepted {
        group.discard_commit(&client).ok();
        bail!("server did not accept the commit: {response}");
    }

    let epoch = group
        .confirm_commit(&client)
        .map_err(|e| anyhow!("merge accepted commit: {e}"))?;
    println!("accepted=true");
    println!("group_id={}", hex::encode(group.id()));
    println!("epoch={epoch}");
    println!("added_devices={}", transport_added.join(","));
    Ok(())
}

async fn send(args: SendArgs) -> Result<()> {
    if args.recipients.is_empty() {
        bail!("at least one --recipients device id is required");
    }
    let client = open_profile(&args.profile, &args.passphrase)?;
    let api = Api::new(&args.server)?;
    let mut group = client
        .load_group(&group_id_from_hex(&args.group)?)
        .map_err(|e| anyhow!("load group: {e}"))?;
    let ciphertext = group
        .send(&client, args.message.as_bytes())
        .map_err(|e| anyhow!("encrypt message: {e}"))?;
    let (status, response) = api
        .signed(
            &client,
            Method::POST,
            "/v1/messages",
            Some(json!({
                "recipients": args.recipients,
                "body": STANDARD.encode(&ciphertext)
            })),
        )
        .await?;
    if !status.is_success() {
        bail!("send failed ({status}): {response}");
    }
    println!(
        "delivered={} group_id={}",
        response
            .get("delivered")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        hex::encode(group.id())
    );
    Ok(())
}

async fn receive(args: ReceiveArgs) -> Result<()> {
    let client = open_profile(&args.profile, &args.passphrase)?;
    let api = Api::new(&args.server)?;
    let path = if args.wait == 0 {
        "/v1/messages".to_string()
    } else {
        format!("/v1/messages?wait={}", args.wait)
    };
    let (status, response) = api.signed(&client, Method::GET, &path, None).await?;
    if !status.is_success() {
        bail!("fetch failed ({status}): {response}");
    }
    let messages = response
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if messages.is_empty() {
        println!("mailbox=empty");
        return Ok(());
    }

    for message in messages {
        let id = required_string(&message, "id")?;
        let raw = STANDARD
            .decode(required_string(&message, "body")?)
            .context("decode mailbox body")?;

        let event: Option<Incoming> = if raw.first() == Some(&0) {
            let mut joined = client
                .join(&raw)
                .map_err(|e| anyhow!("join welcome: {e}"))?;
            println!("welcome: joined group_id={}", hex::encode(joined.id()));
            if joined.should_refresh_keys() {
                println!("group: key refresh recommended after join");
            }
            let _ = &mut joined;
            None
        } else {
            let group_id = envelope_group_id(&raw)?;
            let mut group = client
                .load_group(&group_id)
                .map_err(|e| anyhow!("load message group {}: {e}", hex::encode(&group_id)))?;
            let incoming = group
                .receive(&client, &raw)
                .map_err(|e| anyhow!("decrypt group {}: {e}", hex::encode(&group_id)))?;
            match &incoming {
                Incoming::Message { from, name, body } => {
                    println!(
                        "message group={} from={} name={} body={}",
                        hex::encode(group.id()),
                        from,
                        name,
                        String::from_utf8_lossy(body)
                    );
                }
                Incoming::GroupChanged {
                    added,
                    removed,
                    epoch,
                    own_commit_discarded,
                } => {
                    println!(
                        "group_changed group={} epoch={} added={} removed={} own_commit_discarded={}",
                        hex::encode(group.id()),
                        epoch,
                        added.len(),
                        removed.len(),
                        own_commit_discarded
                    );
                }
                Incoming::OwnCommitMerged { epoch } => {
                    println!(
                        "own_commit_merged group={} epoch={epoch}",
                        hex::encode(group.id())
                    );
                }
                Incoming::RemovedFromGroup => {
                    println!("removed_from_group group={}", hex::encode(group.id()));
                }
                Incoming::HeldForRetry { epoch } => {
                    println!(
                        "held_for_retry group={} epoch={epoch}",
                        hex::encode(group.id())
                    );
                }
                Incoming::SettingsChanged {
                    seq,
                    title,
                    disappearing_seconds,
                } => {
                    println!(
                        "settings_changed group={} seq={seq} title={title:?} disappearing_seconds={disappearing_seconds}",
                        hex::encode(group.id())
                    );
                }
                Incoming::OwnEcho => {
                    println!("own_echo group={}", hex::encode(group.id()));
                }
            }
            Some(incoming)
        };

        if matches!(event, Some(Incoming::HeldForRetry { .. })) {
            // Keep the server mailbox entry. The corresponding commit may
            // arrive later and this same ciphertext must remain retryable.
            continue;
        }
        let (ack_status, ack_body) = api
            .signed(
                &client,
                Method::POST,
                "/v1/messages/ack",
                Some(json!({ "ids": [id] })),
            )
            .await?;
        if !ack_status.is_success() {
            bail!("ack failed ({ack_status}): {ack_body}");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(args) => init(args).await,
        Command::Signup(args) => signup(args).await,
        Command::UploadKeys(args) => upload_keys(args).await,
        Command::Info(args) => info(args).await,
        Command::RecoveryGenerate(args) => recovery_generate(args).await,
        Command::RecoverySetup(args) => recovery_setup(args).await,
        Command::Recovery(args) => recovery(args).await,
        Command::CreateGroup(args) => create_group(args).await,
        Command::Invite(args) => invite(args).await,
        Command::Send(args) => send(args).await,
        Command::Receive(args) => receive(args).await,
    }
}
