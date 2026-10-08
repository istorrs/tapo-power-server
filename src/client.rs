//! Async TPAP client: discover, SPAKE2+ login, encrypted `/ds` requests.
//!
//! All device I/O goes through one mutex, so there is never more than one
//! in-flight request on a session (the CCM sequence counter is not safe for
//! concurrent use).
//!
//! Login safety: the device counts failed logins and locks out. A handshake
//! makes exactly one attempt, and once the device rejects a login (or a
//! protocol error occurs after `pake_register`) the client refuses to contact
//! the device again until the process is restarted.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::{
    auth::{ExtraCrypt, build_credentials, md5_hex, sha256_hex},
    credentials::Credentials,
    error::{TapoError, from_device_code},
    session::{Reply, Session, SessionError},
    spake,
};

const KEEPALIVE_AFTER: Duration = Duration::from_secs(45);
const MAX_PBKDF2_ITERATIONS: u32 = 5_000_000;
/// Login attempts that may end with an unknown outcome before login is disabled.
const MAX_UNRESOLVED_PROOFS: u8 = 3;

impl From<SessionError> for TapoError {
    fn from(e: SessionError) -> Self {
        match e {
            // The counter is never wrapped (that would reuse a nonce); a fresh
            // session is the only way forward.
            SessionError::SequenceExhausted => Self::SessionExpired(e.to_string()),
            other => Self::Protocol(other.to_string()),
        }
    }
}

impl From<spake::SpakeError> for TapoError {
    fn from(e: spake::SpakeError) -> Self {
        Self::Protocol(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// After a login-bearing request is sent, no new handshake is started for
    /// this long unless the previous one succeeded. Guards against hammering
    /// the device (which locks out) after transient failures or interruptions.
    pub login_cooldown: Duration,
    /// Idle time after which a keep-alive request precedes the next command.
    pub keepalive_after: Duration,
}

impl ClientConfig {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 80,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            login_cooldown: Duration::from_secs(30),
            keepalive_after: KEEPALIVE_AFTER,
        }
    }
}

struct Live {
    session: Session,
    ds_url: String,
}

/// Tracks login attempts whose effect on the device's lockout counter is not
/// known with certainty.
#[derive(Default)]
struct LoginGuard {
    /// Set before a login-bearing request is sent and cleared on success, so a
    /// failed *or interrupted* (future dropped) attempt is never retried at once.
    cooldown_until: Option<Instant>,
    /// Proofs sent whose outcome never came back (timeout, reset, or the
    /// request future was dropped). The device may have counted each as a
    /// failure, so after [`MAX_UNRESOLVED_PROOFS`] login is disabled.
    unresolved_proofs: u8,
}

struct Inner {
    live: Option<Live>,
    /// Set after the device rejects a login; no further handshakes are attempted.
    login_blocked: Option<String>,
    guard: LoginGuard,
    last_activity: Instant,
}

pub struct TpapClient {
    config: ClientConfig,
    credentials: Credentials,
    http: reqwest::Client,
    terminal_uuid: String,
    inner: Mutex<Inner>,
}

struct Discovery {
    base_url: String,
    mac_no_sep: String,
    dac: bool,
    pake: Vec<i64>,
    user_hash_type: Option<i64>,
}

fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return "timed out".into();
    }
    let mut msg = String::new();
    let mut src: Option<&dyn std::error::Error> = Some(e);
    while let Some(s) = src {
        if !msg.is_empty() {
            msg.push_str(": ");
        }
        msg.push_str(&s.to_string());
        src = s.source();
    }
    // The request URL of a session request embeds the session id
    // (`/stok=<id>/ds`), and this text ends up in HTTP error bodies and logs.
    if let Some(url) = e.url() {
        msg = msg.replace(url.as_str(), "<device>");
    }
    scrub_session_ids(&msg).to_ascii_lowercase()
}

/// Replace anything that looks like `stok=<value>` with `stok=<redacted>`.
fn scrub_session_ids(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("stok=") {
        out.push_str(&rest[..i]);
        out.push_str("stok=<redacted>");
        let after = &rest[i + "stok=".len()..];
        let end = after
            .find(['/', ')', '"', '\'', ' ', '?', '#'])
            .unwrap_or(after.len());
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// RFC 3986 unreserved characters pass through; everything else is %-encoded
/// (matches .NET's `Uri.EscapeDataString`).
pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn field_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, TapoError> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| TapoError::Protocol(format!("response is missing `{key}`")))
}

fn field_i64(v: &Value, key: &str) -> Result<i64, TapoError> {
    v.get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| TapoError::Protocol(format!("response is missing `{key}`")))
}

fn b64(v: &Value, key: &str) -> Result<Vec<u8>, TapoError> {
    B64.decode(field_str(v, key)?)
        .map_err(|_| TapoError::Protocol(format!("`{key}` is not valid base64")))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], TapoError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .map_err(|_| TapoError::Protocol("random number generation failed".into()))?;
    Ok(buf)
}

/// Check the device envelope's `error_code`, enriching login failures with the
/// lockout budget the device reports.
fn check_error_code(envelope: &Value, context: &str) -> Result<(), TapoError> {
    let code = envelope
        .get("error_code")
        .and_then(Value::as_i64)
        .unwrap_or(-100_000);
    if code == 0 {
        return Ok(());
    }
    match from_device_code(code, context) {
        TapoError::Authentication(mut msg) => {
            if let Some(info) = envelope.get("error_info") {
                for (key, label) in [
                    ("failedAttempts", "failed attempts"),
                    ("remainAttempts", "remaining attempts before lockout"),
                    ("lockedMinute", "locked for minutes"),
                ] {
                    if let Some(n) = info.get(key).and_then(Value::as_i64) {
                        msg.push_str(&format!("; {label}: {n}"));
                    }
                }
            }
            Err(TapoError::Authentication(msg))
        }
        other => Err(other),
    }
}

impl TpapClient {
    pub fn new(config: ClientConfig, credentials: Credentials) -> Result<Self, TapoError> {
        // The device's HTTP parser only recognises `Content-Length` in title
        // case and otherwise ignores the body, so headers must not be lowercased.
        let http = reqwest::Client::builder()
            .http1_title_case_headers()
            .no_proxy()
            // A redirect would resend a POST body (a login proof) and could send
            // device traffic elsewhere; treat 3xx as an error instead.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| TapoError::Transport(describe(&e)))?;
        Ok(Self {
            terminal_uuid: B64.encode(random_bytes::<16>()?),
            config,
            credentials,
            http,
            inner: Mutex::new(Inner {
                live: None,
                login_blocked: None,
                guard: LoginGuard::default(),
                last_activity: Instant::now(),
            }),
        })
    }

    /// Build a device command envelope.
    pub fn envelope(&self, method: &str, params: Option<Value>) -> Value {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let mut v = json!({
            "method": method,
            "request_time_milis": millis,
            "terminal_uuid": self.terminal_uuid,
        });
        if let Some(p) = params {
            v["params"] = p;
        }
        v
    }

    /// Send a command over the established session, handshaking first if
    /// needed. A session-level failure triggers one re-handshake and resend.
    pub async fn request(&self, command: &Value) -> Result<Value, TapoError> {
        let mut inner = self.inner.lock().await;
        self.ensure_session(&mut inner).await?;
        match self.send(&mut inner, command).await {
            Err(e) if e.is_session_error() => {
                inner.live = None;
                self.handshake(&mut inner).await?;
                self.send(&mut inner, command).await
            }
            other => other,
        }
    }

    /// Establish a session now (used by probes and start-up checks).
    pub async fn connect(&self) -> Result<(), TapoError> {
        let mut inner = self.inner.lock().await;
        self.ensure_session(&mut inner).await
    }

    async fn ensure_session(&self, inner: &mut Inner) -> Result<(), TapoError> {
        if inner.live.is_none() {
            return self.handshake(inner).await;
        }
        if inner.last_activity.elapsed() >= self.config.keepalive_after {
            let ping = self.envelope("get_device_info", None);
            match self.send(inner, &ping).await {
                Ok(_) => {}
                Err(e) if e.is_session_error() => {
                    inner.live = None;
                    return self.handshake(inner).await;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn handshake(&self, inner: &mut Inner) -> Result<(), TapoError> {
        if let Some(reason) = &inner.login_blocked {
            return Err(TapoError::Authentication(format!(
                "login disabled after an earlier failure ({reason}); fix the problem and restart"
            )));
        }
        if inner.guard.unresolved_proofs >= MAX_UNRESOLVED_PROOFS {
            return Err(TapoError::Authentication(
                "login disabled: earlier attempts ended with an unknown outcome; restart to retry"
                    .into(),
            ));
        }
        if let Some(until) = inner.guard.cooldown_until {
            let now = Instant::now();
            if now < until {
                return Err(TapoError::Protocol(format!(
                    "an earlier login attempt failed or was interrupted; not retrying for {}s",
                    (until - now).as_secs() + 1
                )));
            }
        }
        inner.live = None;
        match self.handshake_inner(&mut inner.guard).await {
            Ok(live) => {
                inner.live = Some(live);
                inner.guard = LoginGuard::default();
                inner.last_activity = Instant::now();
                Ok(())
            }
            Err(e) => {
                // Only a genuine rejection latches; anything else just cools down.
                if matches!(e, TapoError::Authentication(_)) {
                    inner.login_blocked = Some(e.to_string());
                } else if inner.guard.unresolved_proofs >= MAX_UNRESOLVED_PROOFS {
                    inner.login_blocked = Some(format!(
                        "{MAX_UNRESOLVED_PROOFS} login attempts ended with an unknown outcome, so the device may be close to locking out"
                    ));
                }
                Err(e)
            }
        }
    }

    async fn post_login(
        &self,
        base_url: &str,
        step: &str,
        params: Value,
    ) -> Result<Value, TapoError> {
        let body = json!({ "method": "login", "params": params });
        let resp = self
            .http
            .post(format!("{base_url}/"))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| TapoError::Transport(describe(&e)))?;
        if resp.status().as_u16() != 200 {
            return Err(TapoError::Protocol(format!(
                "{step}: HTTP {}",
                resp.status().as_u16()
            )));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| TapoError::Transport(describe(&e)))?;
        let envelope: Value = serde_json::from_str(&text)
            .map_err(|_| TapoError::Protocol(format!("{step}: response is not JSON")))?;
        check_error_code(&envelope, step)?;
        envelope
            .get("result")
            .cloned()
            .ok_or_else(|| TapoError::Protocol(format!("{step}: response has no result")))
    }

    async fn discover(&self) -> Result<Discovery, TapoError> {
        let first = format!("http://{}:{}", self.config.host, self.config.port);
        let result = self
            .post_login(&first, "discover", json!({ "sub_method": "discover" }))
            .await?;
        let tpap = result
            .get("tpap")
            .ok_or_else(|| TapoError::Protocol("discover: no tpap object".into()))?;
        let tls = tpap.get("tls").and_then(Value::as_i64).unwrap_or(0);
        if tls != 0 {
            return Err(TapoError::Unsupported(
                "device requires TLS for TPAP, which is not implemented".into(),
            ));
        }
        let port = tpap
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(80);
        Ok(Discovery {
            base_url: format!("http://{}:{}", self.config.host, port),
            mac_no_sep: result
                .get("mac")
                .and_then(Value::as_str)
                .unwrap_or("")
                .replace([':', '-'], ""),
            dac: tpap.get("dac").and_then(Value::as_i64) == Some(1),
            pake: tpap
                .get("pake")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_i64).collect())
                .unwrap_or_default(),
            user_hash_type: tpap.get("user_hash_type").and_then(Value::as_i64),
        })
    }

    /// One handshake attempt. `guard` is armed just before the first
    /// login-bearing request (`pake_register`) is sent.
    async fn handshake_inner(&self, guard: &mut LoginGuard) -> Result<Live, TapoError> {
        let disc = self.discover().await?;

        // Prefer the account-password type when offered, even if the device also
        // offers passcode types this implementation does not handle.
        let passcode_type = if disc.pake.iter().any(|p| matches!(p, 1 | 2 | 5)) {
            "userpw"
        } else if disc.pake.contains(&0) {
            return Err(TapoError::Unsupported(
                "device offers the MAC-derived default passcode only; not implemented".into(),
            ));
        } else if disc.pake.contains(&3) {
            return Err(TapoError::Unsupported(
                "shared_token passcode type is not implemented".into(),
            ));
        } else {
            return Err(TapoError::Unsupported(format!(
                "no supported passcode type in {:?}",
                disc.pake
            )));
        };

        let user_random = random_bytes::<32>()?;
        let username = if disc.user_hash_type == Some(1) {
            sha256_hex("admin").to_ascii_uppercase()
        } else {
            md5_hex("admin")
        };

        guard.cooldown_until = Some(Instant::now() + self.config.login_cooldown);
        let reg = self
            .post_login(
                &disc.base_url,
                "pake_register",
                json!({
                    "sub_method": "pake_register",
                    "username": username,
                    "user_random": B64.encode(user_random),
                    "cipher_suites": [1],
                    "encryption": ["aes_128_ccm"],
                    "passcode_type": passcode_type,
                    "stok": null,
                }),
            )
            .await?;

        let dev_random = b64(&reg, "dev_random")?;
        let dev_salt = b64(&reg, "dev_salt")?;
        let dev_share = b64(&reg, "dev_share")?;
        if field_i64(&reg, "cipher_suites")? != 1 {
            return Err(TapoError::Unsupported(
                "device chose a cipher suite other than 1 (P-256/SHA-256)".into(),
            ));
        }
        let encryption = field_str(&reg, "encryption")?
            .to_ascii_lowercase()
            .replace('-', "_");
        if encryption != "aes_128_ccm" {
            return Err(TapoError::Unsupported(format!(
                "unsupported session cipher `{encryption}`"
            )));
        }
        let iterations = u32::try_from(field_i64(&reg, "iterations")?)
            .ok()
            .filter(|n| (1..=MAX_PBKDF2_ITERATIONS).contains(n))
            .ok_or_else(|| {
                TapoError::Protocol("device reported an unreasonable iteration count".into())
            })?;
        let extra: Option<ExtraCrypt> = match reg.get("extra_crypt") {
            Some(v) if !v.is_null() => Some(
                serde_json::from_value(v.clone())
                    .map_err(|_| TapoError::Protocol("extra_crypt is malformed".into()))?,
            ),
            _ => None,
        };

        let credential_string = zeroize::Zeroizing::new(build_credentials(
            extra.as_ref(),
            self.credentials.email(),
            self.credentials.password(),
            &disc.mac_no_sep,
        ));
        // PBKDF2 with a device-chosen iteration count is CPU-bound: keep it off the
        // async workers so /health and other routes stay responsive.
        let w = tokio::task::spawn_blocking(move || {
            spake::derive_w(credential_string.as_bytes(), &dev_salt, iterations)
        })
        .await
        .map_err(|_| TapoError::Protocol("key derivation task failed".into()))??;
        let x = spake::random_scalar()?;
        let hs = spake::finish(&x, &w, &user_random, &dev_random, &dev_share)?;

        let mut share = json!({
            "sub_method": "pake_share",
            "user_share": B64.encode(&hs.user_share),
            "user_confirm": B64.encode(&hs.user_confirm),
        });
        if disc.dac {
            share["dac_nonce"] = json!(B64.encode(random_bytes::<16>()?));
        }
        // Count the proof as unresolved *before* it leaves, so that a dropped
        // future or a lost reply still leaves a record; any answer from the
        // device (even an HTTP error) resolves it.
        guard.unresolved_proofs = guard.unresolved_proofs.saturating_add(1);
        // Slow earlier stages (PBKDF2, a slow device) must not use up the window.
        guard.cooldown_until = Some(Instant::now() + self.config.login_cooldown);
        let sent = self.post_login(&disc.base_url, "pake_share", share).await;
        if !matches!(sent, Err(TapoError::Transport(_))) {
            guard.unresolved_proofs = 0;
        }
        let done = sent?;

        let dev_confirm = b64(&done, "dev_confirm")?;
        if !hs.verify_dev_confirm(&dev_confirm) {
            return Err(TapoError::Protocol(
                "device confirmation did not match".into(),
            ));
        }
        let session_id = done
            .get("sessionId")
            .or_else(|| done.get("stok"))
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| TapoError::Protocol("pake_share: no session id".into()))?;
        let start_seq = u32::try_from(field_i64(&done, "start_seq")?)
            .map_err(|_| TapoError::Protocol("start_seq out of range".into()))?;

        Ok(Live {
            session: Session::new(&hs.shared_key, start_seq),
            ds_url: format!("{}/stok={}/ds", disc.base_url, percent_encode(session_id)),
        })
    }

    async fn send(&self, inner: &mut Inner, command: &Value) -> Result<Value, TapoError> {
        let live = inner
            .live
            .as_mut()
            .ok_or_else(|| TapoError::Protocol("no established session".into()))?;
        let plain = serde_json::to_vec(command).map_err(|e| TapoError::Protocol(e.to_string()))?;
        // The sequence number is consumed even if the request then fails.
        let (seq, body) = live.session.encrypt_request(&plain)?;
        let resp = self
            .http
            .post(&live.ds_url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|e| TapoError::Transport(describe(&e)))?;
        match resp.status().as_u16() {
            200 => {}
            401 => return Err(TapoError::Device { code: -40401 }),
            n => return Err(TapoError::Protocol(format!("request: HTTP {n}"))),
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| TapoError::Transport(describe(&e)))?;
        let (json_bytes, authenticated) = match live.session.decrypt_response(&bytes, seq)? {
            Reply::Plain(b) => (b, false),
            Reply::Decrypted(b) => (b, true),
        };
        let value: Value = serde_json::from_slice(&json_bytes)
            .map_err(|_| TapoError::Protocol("response is not JSON".into()))?;
        check_error_code(&value, "request")?;
        if !authenticated {
            // Plaintext is only legitimate for error envelopes. A plaintext
            // *success* carries no proof of coming from the device.
            return Err(TapoError::Protocol(
                "device sent an unauthenticated success reply; ignoring it".into(),
            ));
        }
        inner.last_activity = Instant::now();
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding_matches_escape_data_string() {
        assert_eq!(percent_encode("AbC-1_2.3~"), "AbC-1_2.3~");
        assert_eq!(percent_encode("a b/c+d="), "a%20b%2Fc%2Bd%3D");
    }

    #[test]
    fn error_code_check_reports_lockout_budget() {
        let env =
            json!({"error_code": -2202, "error_info": {"failedAttempts": 2, "remainAttempts": 3}});
        let err = check_error_code(&env, "pake_share").unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, TapoError::Authentication(_)));
        assert!(
            msg.contains("failed attempts: 2")
                && msg.contains("remaining attempts before lockout: 3")
        );
        assert!(check_error_code(&json!({"error_code": 0}), "x").is_ok());
        assert!(matches!(
            check_error_code(&json!({}), "x"),
            Err(TapoError::Device { code: -100_000 })
        ));
    }

    // ---- end-to-end against the simulated device ----

    use crate::mock::{MockConfig, MockDevice};

    async fn setup(cfg: MockConfig, password: &str) -> (MockDevice, TpapClient) {
        let dev = MockDevice::start(cfg).await;
        let mut config = ClientConfig::new("127.0.0.1");
        config.port = dev.addr.port();
        let creds = Credentials::new("user@example.com".into(), password.into()).unwrap();
        (dev, TpapClient::new(config, creds).unwrap())
    }

    #[tokio::test]
    async fn handshake_and_request_roundtrip() {
        let (dev, client) = setup(MockConfig::default(), "correct horse").await;
        let reply = client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        assert_eq!(reply["result"]["model"], "P316M");
        let st = dev.state.lock().unwrap();
        assert_eq!(st.handshakes, 1);
        assert!(st.saw_dac_nonce);
    }

    #[tokio::test]
    async fn works_with_every_extra_crypt_variant() {
        for extra in [
            None,
            Some(json!({"type": "password_shadow", "params": {"passwd_id": 2}})),
            Some(json!({"type": "password_shadow", "params": {"passwd_id": 3}})),
            Some(
                json!({"type": "password_authkey", "params": {"authkey_tmpkey": "abcdefgh", "authkey_dictionary": "0123456789abcdef"}}),
            ),
        ] {
            let cfg = MockConfig {
                extra_crypt: extra,
                dac: false,
                ..Default::default()
            };
            let (dev, client) = setup(cfg, "correct horse").await;
            client
                .request(&client.envelope("get_device_info", None))
                .await
                .unwrap();
            assert!(!dev.state.lock().unwrap().saw_dac_nonce);
        }
    }

    #[tokio::test]
    async fn sequence_numbers_stay_in_step() {
        let (dev, client) = setup(MockConfig::default(), "correct horse").await;
        for _ in 0..5 {
            client
                .request(&client.envelope("get_device_info", None))
                .await
                .unwrap();
        }
        let st = dev.state.lock().unwrap();
        assert_eq!(st.log.len(), 5);
        assert_eq!(st.handshakes, 1);
    }

    #[tokio::test]
    async fn wrong_password_fails_once_then_locks_out_locally() {
        let (dev, client) = setup(MockConfig::default(), "wrong").await;
        let err = client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap_err();
        assert!(matches!(err, TapoError::Authentication(_)), "{err}");
        assert!(err.to_string().contains("failed attempts: 1"));
        let registers = dev.state.lock().unwrap().registers;
        for _ in 0..3 {
            let again = client
                .request(&client.envelope("get_device_info", None))
                .await
                .unwrap_err();
            assert!(again.to_string().contains("login disabled"));
        }
        let st = dev.state.lock().unwrap();
        assert_eq!(
            st.registers, registers,
            "client must not contact the device again"
        );
        assert_eq!(st.failed_logins, 1);
    }

    #[tokio::test]
    async fn dropped_session_triggers_one_rehandshake() {
        let (dev, client) = setup(MockConfig::default(), "correct horse").await;
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        dev.state.lock().unwrap().drop_session = true;
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        assert_eq!(dev.state.lock().unwrap().handshakes, 2);
    }

    #[tokio::test]
    async fn plain_session_error_triggers_rehandshake_and_resend() {
        let (dev, client) = setup(MockConfig::default(), "correct horse").await;
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        dev.state.lock().unwrap().inject_plain_error = Some(-40401);
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        assert_eq!(dev.state.lock().unwrap().handshakes, 2);
    }

    #[tokio::test]
    async fn non_session_device_errors_are_not_retried() {
        let (dev, client) = setup(MockConfig::default(), "correct horse").await;
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        let err = client
            .request(&client.envelope("nonexistent", None))
            .await
            .unwrap_err();
        assert!(matches!(err, TapoError::Device { code: -1008 }));
        assert_eq!(dev.state.lock().unwrap().handshakes, 1);
    }

    #[tokio::test]
    async fn unsupported_passcode_type_never_sends_login() {
        let cfg = MockConfig {
            pake: vec![0],
            ..Default::default()
        };
        let (dev, client) = setup(cfg, "correct horse").await;
        let err = client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap_err();
        assert!(matches!(err, TapoError::Unsupported(_)));
        assert_eq!(dev.state.lock().unwrap().registers, 0);
    }

    #[tokio::test]
    async fn concurrent_requests_are_serialised() {
        let (dev, client) = setup(MockConfig::default(), "correct horse").await;
        let client = std::sync::Arc::new(client);
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let c = client.clone();
                tokio::spawn(async move { c.request(&c.envelope("get_device_info", None)).await })
            })
            .collect();
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        let st = dev.state.lock().unwrap();
        assert_eq!(st.log.len(), 16);
        assert_eq!(st.handshakes, 1);
    }

    #[tokio::test]
    async fn sends_title_case_headers_on_the_wire() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await;
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut config = ClientConfig::new("127.0.0.1");
        config.port = port;
        let client = TpapClient::new(
            config,
            Credentials::new("a@b.c".into(), "pw".into()).unwrap(),
        )
        .unwrap();
        let _ = client.connect().await; // fails (empty JSON); we only care about the request bytes
        let request = server.await.unwrap();
        assert!(
            request.contains("Content-Length: "),
            "request was: {request}"
        );
        assert!(
            request.contains("Content-Type: application/json"),
            "request was: {request}"
        );
        assert!(
            !request.contains("content-length"),
            "request was: {request}"
        );
    }

    fn quick_config(dev: &MockDevice, cooldown_ms: u64) -> ClientConfig {
        let mut config = ClientConfig::new("127.0.0.1");
        config.port = dev.addr.port();
        config.login_cooldown = Duration::from_millis(cooldown_ms);
        config
    }

    fn client_for(config: ClientConfig) -> TpapClient {
        let creds = Credentials::new("user@example.com".into(), "correct horse".into()).unwrap();
        TpapClient::new(config, creds).unwrap()
    }

    #[tokio::test]
    async fn transient_failure_cools_down_then_recovers_without_latching() {
        let dev = MockDevice::start(MockConfig::default()).await;
        let client = client_for(quick_config(&dev, 300));
        dev.state.lock().unwrap().fail_next_share_http = true;

        let first = client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap_err();
        assert!(matches!(first, TapoError::Protocol(_)), "{first}");
        let registers = dev.state.lock().unwrap().registers;

        // Immediately afterwards the device is left alone...
        let second = client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap_err();
        assert!(second.to_string().contains("not retrying"), "{second}");
        assert_eq!(dev.state.lock().unwrap().registers, registers);

        // ...but the failure was not permanent.
        tokio::time::sleep(Duration::from_millis(350)).await;
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        assert_eq!(dev.state.lock().unwrap().handshakes, 1);
    }

    #[tokio::test]
    async fn interrupted_login_is_not_retried_immediately() {
        let dev = MockDevice::start(MockConfig::default()).await;
        dev.state.lock().unwrap().stall_register = true;
        let client = client_for(quick_config(&dev, 60_000));

        // The caller gives up while pake_register is outstanding: the request
        // future is dropped mid-handshake.
        let cmd = client.envelope("get_device_info", None);
        let outcome = tokio::time::timeout(Duration::from_millis(300), client.request(&cmd)).await;
        assert!(outcome.is_err(), "request should have been cancelled");
        assert_eq!(dev.state.lock().unwrap().registers, 1);

        dev.state.lock().unwrap().stall_register = false;
        let err = client.request(&cmd).await.unwrap_err();
        assert!(err.to_string().contains("not retrying"), "{err}");
        assert_eq!(
            dev.state.lock().unwrap().registers,
            1,
            "no second login attempt"
        );
    }

    #[tokio::test]
    async fn prefers_supported_passcode_type_when_default_is_also_offered() {
        let cfg = MockConfig {
            pake: vec![0, 2],
            ..Default::default()
        };
        let (_dev, client) = setup(cfg, "correct horse").await;
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unauthenticated_plaintext_success_is_rejected() {
        let (dev, client) = setup(MockConfig::default(), "correct horse").await;
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        dev.state.lock().unwrap().inject_plain_success = true;
        let err = client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap_err();
        assert!(matches!(err, TapoError::Protocol(_)), "{err}");
        assert!(err.to_string().contains("unauthenticated"), "{err}");
        // The session is unharmed and no re-login was needed.
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        assert_eq!(dev.state.lock().unwrap().handshakes, 1);
    }

    #[tokio::test]
    async fn repeated_unknown_login_outcomes_disable_login() {
        let dev = MockDevice::start(MockConfig::default()).await;
        dev.state.lock().unwrap().stall_share = true;
        let mut config = quick_config(&dev, 0);
        config.request_timeout = Duration::from_millis(250);
        let client = client_for(config);
        let cmd = client.envelope("get_device_info", None);

        for attempt in 1..=MAX_UNRESOLVED_PROOFS {
            let err = client.request(&cmd).await.unwrap_err();
            assert!(
                matches!(err, TapoError::Transport(_)),
                "attempt {attempt}: {err}"
            );
        }
        assert_eq!(
            dev.state.lock().unwrap().shares,
            u32::from(MAX_UNRESOLVED_PROOFS)
        );

        // Login is now disabled and the device is left alone.
        let err = client.request(&cmd).await.unwrap_err();
        assert!(err.to_string().contains("login disabled"), "{err}");
        assert_eq!(
            dev.state.lock().unwrap().shares,
            u32::from(MAX_UNRESOLVED_PROOFS)
        );
    }

    #[tokio::test]
    async fn answered_proofs_do_not_count_as_unresolved() {
        // A device that answers (here with HTTP 503) has resolved the attempt,
        // so many such failures never trip the unknown-outcome limit.
        let dev = MockDevice::start(MockConfig::default()).await;
        let client = client_for(quick_config(&dev, 0));
        let cmd = client.envelope("get_device_info", None);
        for _ in 0..(MAX_UNRESOLVED_PROOFS + 2) {
            dev.state.lock().unwrap().fail_next_share_http = true;
            assert!(client.request(&cmd).await.is_err());
        }
        client.request(&cmd).await.unwrap();
    }

    #[tokio::test]
    async fn keepalive_failure_that_is_not_a_session_error_does_not_relogin() {
        let dev = MockDevice::start(MockConfig::default()).await;
        let mut config = quick_config(&dev, 0);
        config.keepalive_after = Duration::ZERO; // every command is preceded by a keep-alive
        let client = client_for(config);
        let cmd = client.envelope("get_device_info", None);
        client.request(&cmd).await.unwrap();
        assert_eq!(dev.state.lock().unwrap().handshakes, 1);

        dev.state.lock().unwrap().inject_plain_error = Some(-1008);
        let err = client.request(&cmd).await.unwrap_err();
        assert!(matches!(err, TapoError::Device { code: -1008 }), "{err}");
        assert_eq!(
            dev.state.lock().unwrap().handshakes,
            1,
            "no re-login for a non-session error"
        );
    }

    #[tokio::test]
    async fn exhausted_sequence_numbers_trigger_a_fresh_session() {
        let dev = MockDevice::start(MockConfig::default()).await;
        // The device hands out a session with only two usable sequence numbers.
        dev.state.lock().unwrap().start_seq = Some(u32::MAX - 2);
        let client = client_for(quick_config(&dev, 0));
        let cmd = client.envelope("get_device_info", None);

        client.request(&cmd).await.unwrap();
        client.request(&cmd).await.unwrap();
        assert_eq!(dev.state.lock().unwrap().handshakes, 1);

        // The third request finds the counter exhausted, re-handshakes once and
        // succeeds, instead of leaving a dead session installed.
        client.request(&cmd).await.unwrap();
        assert_eq!(dev.state.lock().unwrap().handshakes, 2);
    }

    #[tokio::test]
    async fn a_replayed_reply_is_not_accepted_as_an_answer() {
        // Covered at the session layer; here we check the client surfaces it as
        // a protocol error rather than a success.
        let (dev, client) = setup(MockConfig::default(), "correct horse").await;
        client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap();
        dev.state.lock().unwrap().replay_previous_reply = true;
        let err = client
            .request(&client.envelope("get_device_info", None))
            .await
            .unwrap_err();
        assert!(matches!(err, TapoError::Protocol(_)), "{err}");
    }

    #[test]
    fn session_ids_are_scrubbed_from_text() {
        assert_eq!(
            scrub_session_ids(
                "error sending request for url (http://10.0.0.5/stok=AbC%2F123/ds): x"
            ),
            "error sending request for url (http://10.0.0.5/stok=<redacted>/ds): x"
        );
        assert_eq!(scrub_session_ids("a stok=XYZ"), "a stok=<redacted>");
        assert_eq!(
            scrub_session_ids("stok=A/ds stok=B/ds"),
            "stok=<redacted>/ds stok=<redacted>/ds"
        );
        assert_eq!(scrub_session_ids("nothing here"), "nothing here");
    }

    #[tokio::test]
    async fn transport_errors_do_not_leak_the_session_id() {
        // A real reqwest connection error for a session-style URL.
        let http = reqwest::Client::new();
        let err = http
            .post("http://127.0.0.1:1/stok=SECRETSESSIONID/ds")
            .send()
            .await
            .unwrap_err();
        let text = describe(&err);
        assert!(!text.to_lowercase().contains("secretsessionid"), "{text}");
        assert!(!text.contains("/ds"), "{text}");
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // B must never be contacted.
        let b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_port = b.local_addr().unwrap().port();
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_port = a.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = a.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let reply = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{b_port}/\r\nContent-Length: 0\r\n\r\n"
            );
            let _ = sock.write_all(reply.as_bytes()).await;
        });
        let mut config = ClientConfig::new("127.0.0.1");
        config.port = a_port;
        let client = TpapClient::new(
            config,
            Credentials::new("a@b.c".into(), "pw".into()).unwrap(),
        )
        .unwrap();
        let err = client.connect().await.unwrap_err();
        assert!(err.to_string().contains("307"), "{err}");
        let second = tokio::time::timeout(Duration::from_millis(300), b.accept()).await;
        assert!(
            second.is_err(),
            "the redirect target must not receive a connection"
        );
    }
}
