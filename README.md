# tapo-power-server

A standalone Rust server that speaks TP-Link's **TPAP** protocol to Tapo
power-strip hardware (developed against the **P316M**) and exposes it over a
small HTTP API, for use as an optional bench-hardware power controller by
[pyhil](https://github.com/ConnectedDevelopment/xtg-generic-linux-test-framework).

Why it exists, protocol notes and decisions: [`DESIGN.md`](./DESIGN.md).
Build plan and status: [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md).

Status: working against real P316M hardware (firmware 1.4.1).

## Build

```sh
cargo build --release                      # dynamic binary
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl   # static binary
```

Tagged releases (`v*`) publish a static Linux x86-64 binary to GitHub Releases.

## Run

```sh
tapo-power-server --port 5019 --device-host 192.168.1.213 \
    --credentials-file ~/.config/tapo-power-server/credentials \
    --token-env TAPO_SERVER_TOKEN
```

| Flag | Meaning |
|---|---|
| `--host` | Address to listen on (default `0.0.0.0`). |
| `--port` | Port to listen on (required; pick one not used by other power servers). |
| `--token-env VAR` | Env var holding a bearer token to require. Unset = open API. |
| `--device-host IP` | Address of the Tapo device (required). |
| `--device-port` | Device HTTP port (default 80). |
| `--credentials-file PATH` | File with `TAPO_EMAIL=` / `TAPO_PASSWORD=` lines. Must be mode `0600`. |
| `--email-env` / `--password-env` | Alternative to the file: env vars holding the account email / password (defaults `TAPO_EMAIL`, `TAPO_PASSWORD`). |

### Credentials

The P316M requires the TP-Link **account** email and password used to set the
plug up in the Tapo app. They authenticate the *local* session only; the
server never talks to the cloud. Consider a dedicated bench account that the
strip is shared to.

The password is never accepted as a command-line argument, never logged and
never included in error messages. Keep the credentials file outside any
repository (for example `~/.config/tapo-power-server/credentials`, mode
`0600`); the server refuses a group- or world-readable file, and refuses the
placeholder values.

**Login lockout safety.** The device counts failed logins and locks out. The
server makes exactly one login attempt per handshake; after the device
rejects a login it stops contacting the device entirely and answers device
routes with errors until you fix the credentials and restart it. It does not
exit on a rejected login, so a supervisor such as systemd will not keep
retrying the login. Transport errors (device offline) do not disable login.

## HTTP API

Ports are **1-based**: 1-6 match the physical outlet labels. Anything else,
including 0, is a `400`.

| Method | Path | Body / query | Success |
|---|---|---|---|
| GET | `/health` | | `{"status":"ok"}` (never touches the device, never needs the token) |
| POST | `/turn_on` | `{"port": N}` | `{"result": true}` |
| POST | `/turn_off` | `{"port": N}` | `{"result": false}` |
| POST | `/toggle` | `{"port": N}` | `{"result": <new state>}` |
| GET | `/get_state?port=N` | | `{"result": true\|false}` |
| POST | `/sequence` | `{"port": N, "steps": [{"state":"on"\|"off","hold_ms":ms?}, ...]}` | `{"result":{"ok":true,"steps":n,"last_result":<state>}}` |

`result` is the outlet's resulting on/off state (`true` = on). `/sequence`
runs all steps as one gesture: no other request can interleave, and a step's
`hold_ms` is waited out before the next step (not after the last).

Errors are `{"error": "...", "error_type": "..."}` with status `400`
(caller mistake: bad or missing port, malformed body), `501` (unsupported by
the device or this implementation) or `500` (anything that went wrong talking
to the device). If a token is configured, every route except `/health`
requires `Authorization: Bearer <token>` or gets `401 {"error":"unauthorized"}`.

## Tests

```sh
cargo test                       # unit + simulated-device tests; no hardware needed
```

The unit tests include known-answer vectors generated with independent
implementations (`tools/gen_spake_vector.py`, Python `cryptography`) and an
in-process simulated device that enforces the CCM sequence number.

### Hardware tests

Skipped unless `TAPO_HW_TEST=1`:

```sh
TAPO_HW_TEST=1 TAPO_HOST=192.168.1.213 cargo test --test hardware -- --nocapture
```

Credentials come from `TAPO_CREDENTIALS_FILE` (default
`~/.config/tapo-power-server/credentials`); `TAPO_HW_PORT` picks the outlet
(default 5). **The suite can only switch ports 2-5**, because real equipment
is typically plugged into the end outlets; it always restores the outlet's
original state. A read-only probe is also available:

```sh
cargo run --bin tapo-probe -- 192.168.1.213
```

## Device quirks worth knowing

- The device's HTTP parser only recognises `Content-Length` in **title case**;
  with a lowercase header it ignores the body and returns a generic HTML page.
  The client therefore sends title-case headers (covered by a wire-level test).
- On the P316M `login/discover` reports passcode type `[2]`, so the MAC-derived
  default passcode is not available and account credentials are required.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
