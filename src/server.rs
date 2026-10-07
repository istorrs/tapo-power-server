//! HTTP API matching pyhil's power-server contract (DESIGN §6).
//!
//! * `GET /health` — liveness only; never touches the device; never authenticated.
//! * `POST /turn_on|/turn_off|/toggle` — JSON `{"port": N}`.
//! * `GET /get_state?port=N`
//! * `POST /sequence` — `{"port": N, "steps": [{"state": "on"|"off", "hold_ms": ms?}, ...]}`
//!
//! Success is `{"result": ...}`; errors are `{"error", "error_type"}` with
//! 400 (caller mistake), 501 (unsupported) or 500 (device trouble). Ports are
//! 1-based. If a bearer token is configured every route except `/health`
//! needs `Authorization: Bearer <token>` (constant-time comparison).

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio_util::task::TaskTracker;

use crate::{
    error::TapoError,
    strip::{Step, Strip},
};

const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub strip: Arc<Strip>,
    pub token: Option<Arc<String>>,
    /// Tracks device operations so shutdown can wait for them to finish.
    pub tracker: TaskTracker,
}

impl AppState {
    pub fn new(strip: Arc<Strip>, token: Option<Arc<String>>) -> Self {
        Self {
            strip,
            token,
            tracker: TaskTracker::new(),
        }
    }
}

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/turn_on", post(turn_on))
        .route("/turn_off", post(turn_off))
        .route("/toggle", post(toggle))
        .route("/get_state", get(get_state))
        .route("/sequence", post(sequence))
        .layer(middleware::from_fn_with_state(state.clone(), require_token));
    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .with_state(state)
}

impl IntoResponse for TapoError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            axum::Json(json!({"error": self.to_string(), "error_type": self.error_type()})),
        )
            .into_response()
    }
}

type Reply = Result<Response, TapoError>;

fn ok(result: Value) -> Response {
    axum::Json(json!({ "result": result })).into_response()
}

fn bad(msg: impl Into<String>) -> TapoError {
    TapoError::InvalidArgument(msg.into())
}

/// Run a device operation to completion even if the HTTP client goes away.
///
/// axum drops a handler's future when the connection closes. A sequence
/// abandoned halfway could leave an outlet in an intermediate state (a device
/// held in reset, say), and an interrupted login could confuse the lockout
/// guard, so device work runs in its own task. The task is registered with
/// `tracker` so that shutdown can wait for it.
async fn detached<T, F>(tracker: &TaskTracker, fut: F) -> Result<T, TapoError>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T, TapoError>> + Send + 'static,
{
    tracker
        .spawn(fut)
        .await
        .map_err(|e| TapoError::Protocol(format!("operation task failed: {e}")))?
}

/// Request body, capped at [`MAX_BODY_BYTES`]. An oversized body is rejected
/// with the API's own JSON error (a caller mistake, so 400) instead of a
/// framework-generated plain-text response.
struct Capped(Bytes);

impl<S: Send + Sync> axum::extract::FromRequest<S> for Capped {
    type Rejection = TapoError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, TapoError> {
        axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
            .await
            .map(Capped)
            .map_err(|_| {
                bad(format!(
                    "request body is too large or unreadable (limit {MAX_BODY_BYTES} bytes)"
                ))
            })
    }
}

async fn require_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    if let Some(expected) = &state.token {
        let given = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !bool::from(given.as_bytes().ct_eq(expected.as_bytes())) {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "unauthorized"})),
            )
                .into_response();
        }
    }
    next.run(req).await
}

async fn health() -> Response {
    axum::Json(json!({"status": "ok"})).into_response()
}

/// An integer JSON value (`2`, not `2.5`, `"2"` or `true`).
fn int_field(v: &Value, key: &str) -> Result<i64, TapoError> {
    v.get(key)
        .ok_or_else(|| bad(format!("missing `{key}`")))?
        .as_i64()
        .ok_or_else(|| bad(format!("`{key}` must be an integer")))
}

fn parse_json(body: &Bytes) -> Result<Value, TapoError> {
    let v: Value =
        serde_json::from_slice(body).map_err(|_| bad("request body must be valid JSON"))?;
    if v.is_object() {
        Ok(v)
    } else {
        Err(bad("request body must be a JSON object"))
    }
}

async fn switch(state: AppState, body: Bytes, on: bool) -> Reply {
    let port = int_field(&parse_json(&body)?, "port")?;
    let strip = state.strip.clone();
    let new_state = detached(&state.tracker, async move { strip.set(port, on).await }).await?;
    Ok(ok(json!(new_state)))
}

async fn turn_on(State(state): State<AppState>, Capped(body): Capped) -> Reply {
    switch(state, body, true).await
}

async fn turn_off(State(state): State<AppState>, Capped(body): Capped) -> Reply {
    switch(state, body, false).await
}

async fn toggle(State(state): State<AppState>, Capped(body): Capped) -> Reply {
    let port = int_field(&parse_json(&body)?, "port")?;
    let strip = state.strip.clone();
    let new_state = detached(&state.tracker, async move { strip.toggle(port).await }).await?;
    Ok(ok(json!(new_state)))
}

async fn get_state(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Reply {
    let port = query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .find_map(|kv| kv.strip_prefix("port="))
        .ok_or_else(|| bad("missing `port` query parameter"))?
        .parse::<i64>()
        .map_err(|_| bad("`port` must be an integer"))?;
    let strip = state.strip.clone();
    let current = detached(&state.tracker, async move { strip.state(port).await }).await?;
    Ok(ok(json!(current)))
}

fn parse_steps(v: &Value) -> Result<Vec<Step>, TapoError> {
    let steps = v
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("`steps` must be an array"))?;
    steps
        .iter()
        .map(|s| {
            let on = match s.get("state").and_then(Value::as_str) {
                Some("on") => true,
                Some("off") => false,
                _ => return Err(bad("each step needs `state` of \"on\" or \"off\"")),
            };
            let hold_ms = match s.get("hold_ms") {
                None | Some(Value::Null) => None,
                Some(h) => {
                    let ms = h.as_f64().filter(|m| m.is_finite() && *m >= 0.0);
                    Some(
                        ms.ok_or_else(|| bad("`hold_ms` must be a non-negative number"))?
                            .round() as u64,
                    )
                }
            };
            Ok(Step { on, hold_ms })
        })
        .collect()
}

async fn sequence(State(state): State<AppState>, Capped(body): Capped) -> Reply {
    let v = parse_json(&body)?;
    let port = int_field(&v, "port")?;
    let steps = parse_steps(&v)?;
    let strip = state.strip.clone();
    let (count, last) = detached(
        &state.tracker,
        async move { strip.sequence(port, &steps).await },
    )
    .await?;
    Ok(ok(json!({"ok": true, "steps": count, "last_result": last})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::{ClientConfig, TpapClient},
        credentials::Credentials,
        mock::{MockConfig, MockDevice},
    };

    struct Harness {
        tracker: TaskTracker,
        dev: MockDevice,
        base: String,
        http: reqwest::Client,
    }

    async fn start(token: Option<&str>, password: &str) -> Harness {
        let dev = MockDevice::start(MockConfig::default()).await;
        let mut config = ClientConfig::new("127.0.0.1");
        config.port = dev.addr.port();
        let creds = Credentials::new("user@example.com".into(), password.into()).unwrap();
        let strip = Arc::new(Strip::new(TpapClient::new(config, creds).unwrap()));
        let state = AppState::new(strip, token.map(|t| Arc::new(t.to_string())));
        let tracker = state.tracker.clone();
        let app = router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Harness {
            tracker,
            dev,
            base: format!("http://{addr}"),
            http: reqwest::Client::new(),
        }
    }

    impl Harness {
        async fn post(&self, path: &str, body: &str) -> (u16, Value) {
            let r = self
                .http
                .post(format!("{}{path}", self.base))
                .body(body.to_string())
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
        }
        async fn get(&self, path: &str) -> (u16, Value) {
            let r = self
                .http
                .get(format!("{}{path}", self.base))
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
        }
    }

    #[tokio::test]
    async fn health_never_touches_the_device() {
        let h = start(None, "correct horse").await;
        let (status, body) = h.get("/health").await;
        assert_eq!((status, body), (200, json!({"status": "ok"})));
        assert_eq!(h.dev.state.lock().unwrap().registers, 0);
    }

    #[tokio::test]
    async fn turn_on_off_toggle_and_get_state() {
        let h = start(None, "correct horse").await;
        assert_eq!(
            h.post("/turn_on", r#"{"port": 3}"#).await,
            (200, json!({"result": true}))
        );
        assert_eq!(
            h.get("/get_state?port=3").await,
            (200, json!({"result": true}))
        );
        assert_eq!(
            h.post("/toggle", r#"{"port": 3}"#).await,
            (200, json!({"result": false}))
        );
        assert_eq!(
            h.post("/turn_off", r#"{"port": 3}"#).await,
            (200, json!({"result": false}))
        );
        assert_eq!(
            h.get("/get_state?port=3").await,
            (200, json!({"result": false}))
        );
        assert_eq!(h.dev.state.lock().unwrap().handshakes, 1);
    }

    #[tokio::test]
    async fn caller_mistakes_are_400_and_never_reach_the_device() {
        let h = start(None, "correct horse").await;
        for body in [
            "",
            "not json",
            "[]",
            "{}",
            r#"{"port": "3"}"#,
            r#"{"port": 2.5}"#,
            r#"{"port": true}"#,
            r#"{"port": 0}"#,
            r#"{"port": 7}"#,
            r#"{"port": -1}"#,
        ] {
            let (status, body_json) = h.post("/turn_on", body).await;
            assert_eq!(status, 400, "body {body:?}");
            assert_eq!(body_json["error_type"], "InvalidArgument");
            assert!(body_json["error"].is_string());
        }
        for path in [
            "/get_state",
            "/get_state?port=x",
            "/get_state?port=0",
            "/get_state?port=9",
        ] {
            assert_eq!(h.get(path).await.0, 400, "{path}");
        }
        assert_eq!(h.dev.state.lock().unwrap().registers, 0);
    }

    #[tokio::test]
    async fn sequence_contract() {
        let h = start(None, "correct horse").await;
        let body = r#"{"port": 4, "steps": [{"state":"on","hold_ms":20},{"state":"off","hold_ms":20.4},{"state":"on"}]}"#;
        assert_eq!(
            h.post("/sequence", body).await,
            (
                200,
                json!({"result": {"ok": true, "steps": 3, "last_result": true}})
            )
        );
        for bad_body in [
            r#"{"port": 4}"#,
            r#"{"port": 4, "steps": []}"#,
            r#"{"port": 4, "steps": [{"state":"maybe"}]}"#,
            r#"{"port": 4, "steps": [{"state":"on","hold_ms":-1}]}"#,
            r#"{"port": 4, "steps": [{"state":"on","hold_ms":"x"}]}"#,
            r#"{"port": 9, "steps": [{"state":"on"}]}"#,
        ] {
            assert_eq!(h.post("/sequence", bad_body).await.0, 400, "{bad_body}");
        }
    }

    #[tokio::test]
    async fn sequence_completes_even_if_the_client_disconnects() {
        let h = start(None, "correct horse").await;
        // The client gives up after 100 ms; the sequence needs about 400 ms.
        let impatient = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let body = r#"{"port": 4, "steps": [{"state":"on","hold_ms":200},{"state":"off","hold_ms":200},{"state":"on"}]}"#;
        let result = impatient
            .post(format!("{}/sequence", h.base))
            .body(body)
            .send()
            .await;
        assert!(result.is_err(), "client should have timed out");

        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        let st = h.dev.state.lock().unwrap();
        let sets: Vec<&String> = st.log.iter().filter(|l| l.starts_with("set")).collect();
        assert_eq!(sets, ["set 4 true", "set 4 false", "set 4 true"]);
        assert!(st.outlets[3], "sequence ran to its final step");
    }

    #[tokio::test]
    async fn shutdown_can_wait_for_operations_whose_client_left() {
        let h = start(None, "correct horse").await;
        let impatient = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let body = r#"{"port": 4, "steps": [{"state":"on","hold_ms":200},{"state":"off","hold_ms":200},{"state":"on"}]}"#;
        assert!(
            impatient
                .post(format!("{}/sequence", h.base))
                .body(body)
                .send()
                .await
                .is_err()
        );
        // This is what main() does after the HTTP server stops: close the
        // tracker and wait. The abandoned sequence must still be running.
        assert!(!h.tracker.is_empty(), "the operation is being tracked");
        h.tracker.close();
        h.tracker.wait().await;
        let st = h.dev.state.lock().unwrap();
        let sets: Vec<&String> = st.log.iter().filter(|l| l.starts_with("set")).collect();
        assert_eq!(sets, ["set 4 true", "set 4 false", "set 4 true"]);
    }

    #[tokio::test]
    async fn oversized_body_gets_the_json_error_envelope() {
        let h = start(None, "correct horse").await;
        let huge = format!(r#"{{"port": 3, "pad": "{}"}}"#, "x".repeat(100 * 1024));
        for path in ["/turn_on", "/turn_off", "/toggle", "/sequence"] {
            let (status, body) = h.post(path, &huge).await;
            assert_eq!(status, 400, "{path}");
            assert_eq!(body["error_type"], "InvalidArgument", "{path}");
            assert!(
                body["error"].as_str().unwrap().contains("too large"),
                "{path}"
            );
        }
        assert_eq!(h.dev.state.lock().unwrap().registers, 0);
    }

    #[tokio::test]
    async fn bearer_token_protects_everything_but_health() {
        let h = start(Some("s3cret"), "correct horse").await;
        assert_eq!(h.get("/health").await.0, 200);
        assert_eq!(
            h.get("/get_state?port=2").await,
            (401, json!({"error": "unauthorized"}))
        );
        let call = |auth: Option<&str>| {
            let mut r = h.http.get(format!("{}/get_state?port=2", h.base));
            if let Some(a) = auth {
                r = r.header("Authorization", a);
            }
            async move { r.send().await.unwrap().status().as_u16() }
        };
        assert_eq!(call(Some("Bearer wrong")).await, 401);
        assert_eq!(call(Some("Bearer s3cret-extra")).await, 401);
        assert_eq!(call(Some("s3cret")).await, 401);
        assert_eq!(call(Some("Bearer ")).await, 401);
        assert_eq!(call(Some("Bearer s3cret")).await, 200);
        assert_eq!(
            h.dev.state.lock().unwrap().handshakes,
            1,
            "only the authorised call reached the device"
        );
    }

    #[tokio::test]
    async fn device_failures_are_500_with_error_type() {
        let h = start(None, "wrong password").await;
        let (status, body) = h.post("/turn_on", r#"{"port": 2}"#).await;
        assert_eq!(status, 500);
        assert_eq!(body["error_type"], "AuthenticationError");
        // Subsequent calls fail fast without contacting the device again.
        let registers = h.dev.state.lock().unwrap().registers;
        assert_eq!(h.post("/turn_on", r#"{"port": 2}"#).await.0, 500);
        assert_eq!(h.dev.state.lock().unwrap().registers, registers);
        // /health still works.
        assert_eq!(h.get("/health").await.0, 200);
    }

    #[tokio::test]
    async fn errors_never_contain_credentials() {
        let h = start(None, "wrong password").await;
        let (_, body) = h.post("/turn_on", r#"{"port": 2}"#).await;
        let text = body.to_string();
        assert!(!text.contains("wrong password") && !text.contains("user@example.com"));
    }

    #[tokio::test]
    async fn concurrent_http_requests_are_serialised() {
        let h = start(None, "correct horse").await;
        let h = Arc::new(h);
        let tasks: Vec<_> = (0..12)
            .map(|i| {
                let h = h.clone();
                tokio::spawn(async move {
                    h.post("/toggle", &format!(r#"{{"port": {}}}"#, 2 + i % 4))
                        .await
                        .0
                })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap(), 200);
        }
        assert_eq!(h.dev.state.lock().unwrap().handshakes, 1);
    }
}
