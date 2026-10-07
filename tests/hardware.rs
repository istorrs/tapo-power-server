//! Real-hardware tests. Skipped unless `TAPO_HW_TEST=1`.
//!
//! Required: `TAPO_HOST=<device ip>`; credentials from `TAPO_CREDENTIALS_FILE`
//! (default `~/.config/tapo-power-server/credentials`).
//! Optional: `TAPO_HW_PORT` (default 5).
//!
//! SAFETY: real equipment is plugged into the strip's end outlets. These
//! tests can only switch ports 2-5 (`HwStrip` asserts this before every
//! state-changing call) and always restore the outlet's original state.
//!
//!   TAPO_HW_TEST=1 TAPO_HOST=192.168.1.213 cargo test --test hardware -- --nocapture

use std::path::PathBuf;

use tapo_power_server::{
    client::{ClientConfig, TpapClient},
    credentials::Credentials,
    strip::{Step, Strip},
};

const ALLOWED_PORTS: std::ops::RangeInclusive<i64> = 2..=5;

/// Wrapper that makes switching ports 1 and 6 impossible from this suite.
struct HwStrip(Strip);

impl HwStrip {
    fn guard(port: i64) {
        assert!(
            ALLOWED_PORTS.contains(&port),
            "hardware tests may only use ports 2-5, got {port}"
        );
    }
    async fn set(&self, port: i64, on: bool) -> bool {
        Self::guard(port);
        self.0.set(port, on).await.expect("set")
    }
    async fn state(&self, port: i64) -> bool {
        self.0.state(port).await.expect("state")
    }
    async fn sequence(&self, port: i64, steps: &[Step]) {
        Self::guard(port);
        self.0.sequence(port, steps).await.expect("sequence");
    }
}

fn credentials_path() -> PathBuf {
    std::env::var_os("TAPO_CREDENTIALS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                .join(".config/tapo-power-server/credentials")
        })
}

#[tokio::test]
async fn hardware_suite() {
    if std::env::var("TAPO_HW_TEST").as_deref() != Ok("1") {
        eprintln!("skipping hardware tests (set TAPO_HW_TEST=1 to run)");
        return;
    }
    let host = std::env::var("TAPO_HOST").expect("TAPO_HOST must be set");
    // Default only when the variable is absent. A malformed value must stop the
    // run before the device is contacted: guessing could switch another outlet.
    let port: i64 = match std::env::var("TAPO_HW_PORT") {
        Ok(v) => v
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("TAPO_HW_PORT must be an integer 2-5, got {v:?}")),
        Err(std::env::VarError::NotPresent) => 5,
        Err(e) => panic!("cannot read TAPO_HW_PORT: {e}"),
    };
    assert!(
        ALLOWED_PORTS.contains(&port),
        "TAPO_HW_PORT must be within 2-5"
    );

    let creds = Credentials::from_file(&credentials_path()).expect("credentials");
    let client = TpapClient::new(ClientConfig::new(host), creds).expect("client");
    let strip = HwStrip(Strip::new(client));

    // Read-only: six outlets, positions 1..=6.
    let children = strip.0.states().await.expect("states");
    assert_eq!(children.len(), 6);
    assert_eq!(
        children.iter().map(|c| c.position).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6]
    );

    // Many rapid requests on one session: exercises sequence-number handling.
    for _ in 0..25 {
        strip.state(port).await;
    }

    // State-changing checks run in a spawned task so a failed assertion is
    // caught as a JoinError; the outlet is restored either way.
    let strip = std::sync::Arc::new(strip);
    let original = strip.state(port).await;
    let outcome = tokio::spawn(exercise(strip.clone(), port, original)).await;
    strip.set(port, original).await;
    if let Err(e) = outcome {
        panic!("hardware assertion failed (original state restored): {e}");
    }
}

async fn exercise(s: std::sync::Arc<HwStrip>, port: i64, original: bool) {
    assert_eq!(s.set(port, !original).await, !original);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(s.state(port).await, !original, "state after switching");
    assert_eq!(s.set(port, original).await, original);
    assert_eq!(s.state(port).await, original, "state after restoring");

    // Atomic sequence: flip, hold, restore.
    s.sequence(
        port,
        &[
            Step {
                on: !original,
                hold_ms: Some(700),
            },
            Step {
                on: original,
                hold_ms: None,
            },
        ],
    )
    .await;
    assert_eq!(s.state(port).await, original, "state after sequence");
}
