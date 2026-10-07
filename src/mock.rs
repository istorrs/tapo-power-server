//! In-process simulated TPAP device for tests (`cfg(test)` only).
//!
//! It implements the device side of the handshake and an encrypted `/ds`
//! endpoint with a six-outlet strip, strictly enforcing the request sequence
//! number, so client logic (handshake, retries, lockout guard, sequencing,
//! outlet commands) can be tested without hardware.

use std::sync::{Arc, Mutex};

use axum::{Router, body::Bytes, extract::State, http::Uri, response::IntoResponse};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use p256::{ProjectivePoint, Scalar};
use serde_json::{Value, json};

use crate::{
    auth::build_credentials,
    session::{Reply, Session},
    spake,
};

pub const MOCK_MAC: &str = "58D81266B9EC";
pub const START_SEQ: u32 = 100;

pub struct MockConfig {
    pub email: String,
    pub password: String,
    pub extra_crypt: Option<Value>,
    pub pake: Vec<i64>,
    pub dac: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            email: "user@example.com".into(),
            password: "correct horse".into(),
            extra_crypt: Some(
                json!({"type": "password_sha_with_salt", "params": {"sha_name": 0, "sha_salt": "TmFDbA=="}}),
            ),
            pake: vec![2],
            dac: true,
        }
    }
}

#[derive(Default)]
pub struct MockState {
    pub cfg: Option<MockConfig>,
    pub port: u16,
    pub registers: u32,
    pub failed_logins: u32,
    pub handshakes: u32,
    /// Methods of every authenticated command received, in order.
    pub log: Vec<String>,
    pub outlets: Vec<bool>,
    /// Respond to the next `/ds` request with this plaintext error code.
    pub inject_plain_error: Option<i64>,
    /// Forget the session (as an idle device does).
    pub drop_session: bool,
    pub saw_dac_nonce: bool,
    /// Hold `pake_register` replies for a long time (simulates a stuck login).
    pub stall_register: bool,
    /// Answer the next `pake_share` with HTTP 503.
    pub fail_next_share_http: bool,
    /// Hold `pake_share` replies for a long time (outcome unknown to the client).
    pub stall_share: bool,
    /// Number of `pake_share` requests that reached the device.
    pub shares: u32,
    /// Omit the wrapped child `error_code` from switch replies.
    pub omit_child_error_code: bool,
    /// Make switch replies report this error code for the wrapped child.
    pub child_error_code: Option<i64>,
    /// Answer the next authenticated request with a forged *plaintext* success.
    pub inject_plain_success: bool,
    // handshake scratch
    pending: Option<Pending>,
    session: Option<DevSession>,
}

struct Pending {
    user_random: Vec<u8>,
    dev_random: Vec<u8>,
    y: Scalar,
    w0: Scalar,
    w1: Scalar,
    dev_share: Vec<u8>,
}

struct DevSession {
    id: String,
    shared: Vec<u8>,
    expected_seq: u32,
}

pub struct MockDevice {
    pub addr: std::net::SocketAddr,
    pub state: Arc<Mutex<MockState>>,
}

type Shared = Arc<Mutex<MockState>>;

impl MockDevice {
    pub async fn start(cfg: MockConfig) -> Self {
        let state = Arc::new(Mutex::new(MockState {
            cfg: Some(cfg),
            outlets: vec![false; 6],
            ..Default::default()
        }));
        let app = Router::new().fallback(handle).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        state.lock().unwrap().port = addr.port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { addr, state }
    }
}

fn ok(result: Value) -> Value {
    json!({"error_code": 0, "result": result})
}

fn code(c: i64) -> Value {
    json!({"error_code": c})
}

async fn handle(State(st): State<Shared>, uri: Uri, body: Bytes) -> impl IntoResponse {
    use axum::http::StatusCode;
    let parsed: Value = if uri.path() == "/" {
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    let sub = parsed["params"]["sub_method"].as_str().unwrap_or("");
    let stall = {
        let mut g = st.lock().unwrap();
        if sub == "pake_register" {
            g.registers += 1; // count on arrival, before any stall
        }
        if sub == "pake_share" {
            g.shares += 1;
        }
        (sub == "pake_register" && g.stall_register) || (sub == "pake_share" && g.stall_share)
    };
    if stall {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
    let mut st = st.lock().unwrap();
    if sub == "pake_share" && std::mem::take(&mut st.fail_next_share_http) {
        return (StatusCode::SERVICE_UNAVAILABLE, vec![]);
    }
    if uri.path() == "/" {
        let reply = login(&mut st, &parsed["params"]);
        return (StatusCode::OK, reply.to_string().into_bytes());
    }
    ds(&mut st, uri.path(), &body)
}

fn login(st: &mut MockState, params: &Value) -> Value {
    match params["sub_method"].as_str().unwrap_or("") {
        "discover" => {
            let cfg = st.cfg.as_ref().unwrap();
            ok(
                json!({"sub_method": "discover", "tpap_preferred": true, "mac": MOCK_MAC,
                "tpap": {"tls": 0, "dac": i32::from(cfg.dac), "noc": 1, "pake": cfg.pake, "port": st.port}}),
            )
        }
        "pake_register" => {
            let cfg = st.cfg.as_ref().unwrap();
            let credential = build_credentials(
                cfg.extra_crypt
                    .as_ref()
                    .map(|v| serde_json::from_value(v.clone()).unwrap())
                    .as_ref(),
                &cfg.email,
                &cfg.password,
                MOCK_MAC,
            );
            let salt: Vec<u8> = (1u8..=16).collect();
            let w = spake::derive_w(credential.as_bytes(), &salt, 1000).unwrap();
            let y = spake::random_scalar().unwrap();
            let n = spake::decode_point(&spake::N_COMPRESSED).unwrap();
            let dev_share = spake::encode_point(&(ProjectivePoint::GENERATOR * y + n * w.w0));
            let dev_random = vec![0x5a; 32];
            let reply = ok(json!({
                "dev_random": B64.encode(&dev_random), "dev_salt": B64.encode(&salt),
                "dev_share": B64.encode(&dev_share), "cipher_suites": 1, "iterations": 1000,
                "encryption": "aes_128_ccm", "extra_crypt": cfg.extra_crypt,
            }));
            st.pending = Some(Pending {
                user_random: B64
                    .decode(params["user_random"].as_str().unwrap_or(""))
                    .unwrap_or_default(),
                dev_random,
                y,
                w0: w.w0,
                w1: w.w1,
                dev_share,
            });
            reply
        }
        "pake_share" => {
            st.saw_dac_nonce = params.get("dac_nonce").is_some();
            let Some(p) = st.pending.take() else {
                return code(-1501);
            };
            let l_enc = B64
                .decode(params["user_share"].as_str().unwrap_or(""))
                .unwrap_or_default();
            let user_confirm = B64
                .decode(params["user_confirm"].as_str().unwrap_or(""))
                .unwrap_or_default();
            let Ok(l) = spake::decode_point(&l_enc) else {
                return code(-2203);
            };
            let m = spake::decode_point(&spake::M_COMPRESSED).unwrap();
            let n = spake::decode_point(&spake::N_COMPRESSED).unwrap();
            let z = (l - m * p.w0) * p.y;
            let v = ProjectivePoint::GENERATOR * p.w1 * p.y;
            let th = spake::transcript_hash(
                &p.user_random,
                &p.dev_random,
                &m,
                &n,
                &l_enc,
                &p.dev_share,
                &z,
                &v,
                &p.w0,
            );
            let (kc_a, kc_b, shared) = spake::confirmation_material(&th);
            if spake::hmac_sha256(&kc_a, &p.dev_share) != user_confirm {
                st.failed_logins += 1;
                return json!({"error_code": -2203, "error_info": {"failedAttempts": st.failed_logins, "remainAttempts": 5i64 - i64::from(st.failed_logins)}});
            }
            st.handshakes += 1;
            let id = format!("SESSION{}+/=", st.handshakes);
            st.session = Some(DevSession {
                id: id.clone(),
                shared: shared.to_vec(),
                expected_seq: START_SEQ,
            });
            ok(
                json!({"dev_confirm": B64.encode(spake::hmac_sha256(&kc_b, &l_enc)), "sessionId": id, "start_seq": START_SEQ}),
            )
        }
        _ => code(-1),
    }
}

fn ds(st: &mut MockState, path: &str, body: &[u8]) -> (axum::http::StatusCode, Vec<u8>) {
    use axum::http::StatusCode;
    if std::mem::take(&mut st.drop_session) {
        st.session = None;
    }
    let Some(sess) = st.session.as_mut() else {
        return (StatusCode::UNAUTHORIZED, vec![]);
    };
    let expected_path = format!("/stok={}/ds", crate::client::percent_encode(&sess.id));
    if path != expected_path {
        return (StatusCode::UNAUTHORIZED, vec![]);
    }
    if let Some(c) = st.inject_plain_error.take() {
        return (StatusCode::OK, code(c).to_string().into_bytes());
    }
    let seq = u32::from_be_bytes(body[..4].try_into().unwrap());
    if seq != sess.expected_seq {
        return (StatusCode::OK, code(-40413).to_string().into_bytes());
    }
    let device = Session::new(&sess.shared, 0);
    let Ok(Reply::Decrypted(plain)) = device.decrypt_response(body, seq) else {
        return (StatusCode::OK, code(-40413).to_string().into_bytes());
    };
    sess.expected_seq = seq + 1;
    let shared = sess.shared.clone();
    if std::mem::take(&mut st.inject_plain_success) {
        return (
            StatusCode::OK,
            ok(json!({"model": "forged"})).to_string().into_bytes(),
        );
    }
    let req: Value = serde_json::from_slice(&plain).unwrap();
    let reply = command(st, &req);
    let (_, sealed) = Session::new(&shared, seq)
        .encrypt_request(reply.to_string().as_bytes())
        .unwrap();
    (StatusCode::OK, sealed)
}

fn child_id(i: usize) -> String {
    format!("CHILD{}", i + 1)
}

fn command(st: &mut MockState, req: &Value) -> Value {
    let method = req["method"].as_str().unwrap_or("").to_string();
    st.log.push(method.clone());
    match method.as_str() {
        "get_device_info" => ok(json!({"model": "P316M", "device_on": true})),
        "get_child_device_list" => {
            let list: Vec<Value> = st
                .outlets
                .iter()
                .enumerate()
                .map(|(i, on)| json!({"device_id": child_id(i), "position": i + 1, "device_on": on, "nickname": format!("Plug {}", i + 1)}))
                .collect();
            ok(json!({"child_device_list": list, "start_index": 0, "sum": 6}))
        }
        "control_child" => {
            let id = req["params"]["device_id"].as_str().unwrap_or("");
            let Some(i) = (0..6).find(|i| child_id(*i) == id) else {
                return code(-1008);
            };
            let inner = &req["params"]["requestData"];
            if inner["method"] != "set_device_info" {
                return code(-1008);
            }
            let Some(on) = inner["params"]["device_on"].as_bool() else {
                return code(-1008);
            };
            if let Some(c) = st.child_error_code {
                return ok(json!({"responseData": {"error_code": c}}));
            }
            st.log.push(format!("set {} {}", i + 1, on));
            st.outlets[i] = on;
            if st.omit_child_error_code {
                return ok(json!({"responseData": {"result": {}}}));
            }
            ok(json!({"responseData": {"error_code": 0}}))
        }
        _ => code(-1008),
    }
}
