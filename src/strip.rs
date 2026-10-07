//! Outlet-level operations on a multi-outlet Tapo strip (P316M).
//!
//! Ports are **1-based** (1..=6), matching the physical outlet labels and the
//! device's own `position` field. Every operation holds `op` for its full
//! duration so a toggle (read then write) or a sequence is atomic with
//! respect to every other request, on top of the per-request serialisation
//! inside [`TpapClient`].

use std::{collections::HashMap, time::Duration};

use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::{client::TpapClient, error::TapoError};

pub const PORT_COUNT: u8 = 6;
const MAX_HOLD_MS: u64 = 3_600_000;
/// Cap on the summed holds of one sequence, since it holds the operation lock.
const MAX_TOTAL_HOLD_MS: u64 = 3_600_000;
const MAX_STEPS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    pub position: u8,
    pub device_id: String,
    pub on: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub on: bool,
    pub hold_ms: Option<u64>,
}

pub struct Strip {
    client: TpapClient,
    /// Held for the whole of every operation; guards the port -> device_id cache.
    op: Mutex<HashMap<u8, String>>,
}

pub fn check_port(port: i64) -> Result<u8, TapoError> {
    u8::try_from(port)
        .ok()
        .filter(|p| (1..=PORT_COUNT).contains(p))
        .ok_or_else(|| {
            TapoError::InvalidArgument(format!(
                "port must be between 1 and {PORT_COUNT}, got {port}"
            ))
        })
}

/// Parse the device's child list. Every field that decides *which* outlet a
/// command targets or what state is reported must be present and well-formed:
/// guessing (list order, "off") could switch the wrong outlet or fabricate a
/// state, so anything else is a protocol error.
fn parse_children(list: &[Value]) -> Result<Vec<Child>, TapoError> {
    let mut children: Vec<Child> = Vec::with_capacity(list.len());
    for c in list {
        let device_id = c
            .get("device_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| TapoError::Protocol("child entry has no device_id".into()))?
            .to_string();
        let position = c
            .get("position")
            .and_then(Value::as_i64)
            .and_then(|p| u8::try_from(p).ok())
            .filter(|p| (1..=PORT_COUNT).contains(p))
            .ok_or_else(|| {
                TapoError::Protocol(format!(
                    "child entry has no valid `position` (expected an integer 1..={PORT_COUNT})"
                ))
            })?;
        let on = c
            .get("device_on")
            .and_then(Value::as_bool)
            .ok_or_else(|| TapoError::Protocol("child entry has no boolean `device_on`".into()))?;
        if children
            .iter()
            .any(|k| k.position == position || k.device_id == device_id)
        {
            return Err(TapoError::Protocol(
                "child list repeats a position or device_id".into(),
            ));
        }
        children.push(Child {
            position,
            device_id,
            on,
        });
    }
    Ok(children)
}

impl Strip {
    pub fn new(client: TpapClient) -> Self {
        Self {
            client,
            op: Mutex::new(HashMap::new()),
        }
    }

    pub fn client(&self) -> &TpapClient {
        &self.client
    }

    /// Fetch the child list (paged until `sum` entries are collected).
    async fn fetch_children(&self) -> Result<Vec<Child>, TapoError> {
        let mut raw: Vec<Value> = Vec::new();
        loop {
            let params = (!raw.is_empty()).then(|| json!({ "start_index": raw.len() }));
            let reply = self
                .client
                .request(&self.client.envelope("get_child_device_list", params))
                .await?;
            let result = &reply["result"];
            let page = result["child_device_list"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let sum = result["sum"].as_u64().unwrap_or(0) as usize;
            let got = page.len();
            raw.extend(page);
            if got == 0 || raw.len() >= sum || raw.len() >= 64 {
                break;
            }
        }
        parse_children(&raw)
    }

    async fn refresh(&self, cache: &mut HashMap<u8, String>) -> Result<Vec<Child>, TapoError> {
        let children = self.fetch_children().await?;
        cache.clear();
        cache.extend(children.iter().map(|c| (c.position, c.device_id.clone())));
        Ok(children)
    }

    async fn device_id(
        &self,
        cache: &mut HashMap<u8, String>,
        port: u8,
    ) -> Result<String, TapoError> {
        if let Some(id) = cache.get(&port) {
            return Ok(id.clone());
        }
        self.refresh(cache).await?;
        cache.get(&port).cloned().ok_or_else(|| {
            TapoError::Protocol(format!("device does not report an outlet at port {port}"))
        })
    }

    async fn set_locked(
        &self,
        cache: &mut HashMap<u8, String>,
        port: u8,
        on: bool,
    ) -> Result<bool, TapoError> {
        let id = self.device_id(cache, port).await?;
        let command = self.client.envelope(
            "control_child",
            Some(json!({
                "device_id": id,
                "requestData": { "method": "set_device_info", "params": { "device_on": on } },
            })),
        );
        let reply = self.client.request(&command).await?;
        // The wrapped child's own result carries its own error_code. The P316M
        // spells the key `responseData`; `response_data` is accepted too. It must
        // be present: a missing code is not an acknowledgement.
        let wrapped = reply["result"]
            .get("responseData")
            .or_else(|| reply["result"].get("response_data"));
        let inner_code = wrapped
            .and_then(|w| w["error_code"].as_i64())
            .ok_or_else(|| {
                TapoError::Protocol("switch reply carries no child error_code".into())
            })?;
        if inner_code != 0 {
            return Err(TapoError::Device { code: inner_code });
        }
        Ok(on)
    }

    async fn state_locked(
        &self,
        cache: &mut HashMap<u8, String>,
        port: u8,
    ) -> Result<bool, TapoError> {
        let children = self.refresh(cache).await?;
        children
            .iter()
            .find(|c| c.position == port)
            .map(|c| c.on)
            .ok_or_else(|| {
                TapoError::Protocol(format!("device does not report an outlet at port {port}"))
            })
    }

    pub async fn set(&self, port: i64, on: bool) -> Result<bool, TapoError> {
        let port = check_port(port)?;
        let mut cache = self.op.lock().await;
        self.set_locked(&mut cache, port, on).await
    }

    pub async fn state(&self, port: i64) -> Result<bool, TapoError> {
        let port = check_port(port)?;
        let mut cache = self.op.lock().await;
        self.state_locked(&mut cache, port).await
    }

    pub async fn states(&self) -> Result<Vec<Child>, TapoError> {
        let mut cache = self.op.lock().await;
        self.refresh(&mut cache).await
    }

    /// Flip the outlet; returns the new state.
    pub async fn toggle(&self, port: i64) -> Result<bool, TapoError> {
        let port = check_port(port)?;
        let mut cache = self.op.lock().await;
        let current = self.state_locked(&mut cache, port).await?;
        self.set_locked(&mut cache, port, !current).await
    }

    /// Run all steps as one gesture; no other request can interleave. The
    /// `hold_ms` of a step is waited out before the *next* step.
    pub async fn sequence(
        &self,
        port: i64,
        steps: &[Step],
    ) -> Result<(usize, Option<bool>), TapoError> {
        let port = check_port(port)?;
        if steps.is_empty() || steps.len() > MAX_STEPS {
            return Err(TapoError::InvalidArgument(format!(
                "steps must contain 1..={MAX_STEPS} entries"
            )));
        }
        if steps
            .iter()
            .any(|s| s.hold_ms.is_some_and(|h| h > MAX_HOLD_MS))
        {
            return Err(TapoError::InvalidArgument(format!(
                "hold_ms must be at most {MAX_HOLD_MS}"
            )));
        }
        // The last step's hold is never waited out, so it does not count.
        let total: u64 = steps[..steps.len() - 1]
            .iter()
            .filter_map(|s| s.hold_ms)
            .sum();
        if total > MAX_TOTAL_HOLD_MS {
            return Err(TapoError::InvalidArgument(format!(
                "total hold time must be at most {MAX_TOTAL_HOLD_MS} ms"
            )));
        }
        let mut cache = self.op.lock().await;
        let mut last = None;
        for (i, step) in steps.iter().enumerate() {
            last = Some(self.set_locked(&mut cache, port, step.on).await?);
            if let (Some(ms), true) = (step.hold_ms, i + 1 < steps.len()) {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
        }
        Ok((steps.len(), last))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::ClientConfig,
        credentials::Credentials,
        mock::{MockConfig, MockDevice},
    };

    async fn strip() -> (MockDevice, Strip) {
        let dev = MockDevice::start(MockConfig::default()).await;
        let mut config = ClientConfig::new("127.0.0.1");
        config.port = dev.addr.port();
        let creds = Credentials::new("user@example.com".into(), "correct horse".into()).unwrap();
        (dev, Strip::new(TpapClient::new(config, creds).unwrap()))
    }

    #[test]
    fn port_validation() {
        for bad in [-1, 0, 7, 256, i64::MAX] {
            assert!(
                matches!(check_port(bad), Err(TapoError::InvalidArgument(_))),
                "{bad}"
            );
        }
        for good in 1..=6 {
            assert_eq!(check_port(good).unwrap(), good as u8);
        }
    }

    #[test]
    fn child_list_must_be_complete_and_unambiguous() {
        let good = json!({"device_id": "A", "position": 2, "device_on": true});
        assert_eq!(
            parse_children(std::slice::from_ref(&good)).unwrap(),
            vec![Child {
                position: 2,
                device_id: "A".into(),
                on: true
            }]
        );
        for (name, bad) in [
            ("no position", json!({"device_id": "A", "device_on": true})),
            (
                "string position",
                json!({"device_id": "A", "position": "2", "device_on": true}),
            ),
            (
                "position 0",
                json!({"device_id": "A", "position": 0, "device_on": true}),
            ),
            (
                "position 7",
                json!({"device_id": "A", "position": 7, "device_on": true}),
            ),
            ("no device_on", json!({"device_id": "A", "position": 2})),
            (
                "numeric device_on",
                json!({"device_id": "A", "position": 2, "device_on": 1}),
            ),
            ("no device_id", json!({"position": 2, "device_on": true})),
            (
                "empty device_id",
                json!({"device_id": "", "position": 2, "device_on": true}),
            ),
        ] {
            assert!(
                matches!(parse_children(&[bad]), Err(TapoError::Protocol(_))),
                "{name}"
            );
        }
        let dup_pos = json!({"device_id": "B", "position": 2, "device_on": false});
        assert!(parse_children(&[good.clone(), dup_pos]).is_err());
        let dup_id = json!({"device_id": "A", "position": 3, "device_on": false});
        assert!(parse_children(&[good, dup_id]).is_err());
    }

    #[tokio::test]
    async fn missing_child_error_code_is_not_an_acknowledgement() {
        let (dev, strip) = strip().await;
        dev.state.lock().unwrap().omit_child_error_code = true;
        let err = strip.set(3, true).await.unwrap_err();
        assert!(matches!(err, TapoError::Protocol(_)), "{err}");
    }

    #[tokio::test]
    async fn child_failure_inside_a_successful_reply_is_an_error() {
        let (dev, strip) = strip().await;
        dev.state.lock().unwrap().child_error_code = Some(-1008);
        let err = strip.set(3, true).await.unwrap_err();
        assert!(matches!(err, TapoError::Device { code: -1008 }), "{err}");
        assert!(
            !dev.state.lock().unwrap().outlets[2],
            "the outlet was not switched"
        );
    }

    #[tokio::test]
    async fn set_and_read_back() {
        let (dev, strip) = strip().await;
        assert!(!strip.state(3).await.unwrap());
        assert!(strip.set(3, true).await.unwrap());
        assert!(strip.state(3).await.unwrap());
        assert!(!strip.state(2).await.unwrap(), "other outlets untouched");
        strip.set(3, false).await.unwrap();
        assert_eq!(dev.state.lock().unwrap().outlets, vec![false; 6]);
    }

    #[tokio::test]
    async fn toggle_flips_and_returns_new_state() {
        let (_dev, strip) = strip().await;
        assert!(strip.toggle(4).await.unwrap());
        assert!(!strip.toggle(4).await.unwrap());
    }

    #[tokio::test]
    async fn invalid_ports_never_reach_the_device() {
        let (dev, strip) = strip().await;
        assert!(strip.set(0, true).await.is_err());
        assert!(strip.set(7, true).await.is_err());
        assert!(strip.state(99).await.is_err());
        assert_eq!(dev.state.lock().unwrap().handshakes, 0);
    }

    #[tokio::test]
    async fn sequence_runs_all_steps_in_order() {
        let (dev, strip) = strip().await;
        let steps = [
            Step {
                on: true,
                hold_ms: Some(30),
            },
            Step {
                on: false,
                hold_ms: Some(30),
            },
            Step {
                on: true,
                hold_ms: None,
            },
        ];
        let started = std::time::Instant::now();
        let (n, last) = strip.sequence(2, &steps).await.unwrap();
        assert_eq!((n, last), (3, Some(true)));
        assert!(started.elapsed() >= Duration::from_millis(60));
        let st = dev.state.lock().unwrap();
        let sets: Vec<&String> = st.log.iter().filter(|l| l.starts_with("set")).collect();
        assert_eq!(sets, ["set 2 true", "set 2 false", "set 2 true"]);
    }

    #[tokio::test]
    async fn sequence_rejects_bad_input() {
        let (_dev, strip) = strip().await;
        assert!(strip.sequence(2, &[]).await.is_err());
        let too_long = [Step {
            on: true,
            hold_ms: Some(MAX_HOLD_MS + 1),
        }];
        assert!(matches!(
            strip.sequence(2, &too_long).await,
            Err(TapoError::InvalidArgument(_))
        ));
    }

    #[tokio::test]
    async fn sequence_total_hold_is_capped() {
        let (dev, strip) = strip().await;
        let steps: Vec<Step> = (0..5)
            .map(|_| Step {
                on: true,
                hold_ms: Some(MAX_HOLD_MS),
            })
            .collect();
        assert!(matches!(
            strip.sequence(2, &steps).await,
            Err(TapoError::InvalidArgument(_))
        ));
        assert_eq!(dev.state.lock().unwrap().handshakes, 0);
    }

    #[tokio::test]
    async fn sequences_do_not_interleave() {
        let (dev, strip) = strip().await;
        let strip = std::sync::Arc::new(strip);
        let mk = |port: i64| {
            let s = strip.clone();
            tokio::spawn(async move {
                let steps = [
                    Step {
                        on: true,
                        hold_ms: Some(20),
                    },
                    Step {
                        on: false,
                        hold_ms: Some(20),
                    },
                    Step {
                        on: true,
                        hold_ms: None,
                    },
                ];
                s.sequence(port, &steps).await
            })
        };
        let (a, b) = (mk(2), mk(3));
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();
        let st = dev.state.lock().unwrap();
        let ports: Vec<char> = st
            .log
            .iter()
            .filter(|l| l.starts_with("set"))
            .map(|l| l.chars().nth(4).unwrap())
            .collect();
        // Each sequence's three sets are contiguous.
        assert!(
            ports == ['2', '2', '2', '3', '3', '3'] || ports == ['3', '3', '3', '2', '2', '2'],
            "{ports:?}"
        );
    }
}
