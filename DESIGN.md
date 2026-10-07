# tapo-power-server — design

Standalone Rust power-control server for TP-Link Tapo devices that speak the
**TPAP** protocol (the "Encrypt Type: TPAP" generation, newer than KLAP), to
be consumed by `pyhil` (`ConnectedDevelopment/xtg-generic-linux-test-framework`)
as one more optional bench-hardware power controller.

Read this whole document before writing code. It is written so you can start
from zero context on the investigation that led here.

## 1. Why this exists

pyhil is a hardware-in-the-loop Python test framework. It controls DUT power
through named outlets on various controller types (relay boards, USB hubs,
smart plugs, PDUs). One existing controller is a TP-Link Kasa HS100 smart
plug — found to be unreliably flaky in practice. The user bought a **TP-Link
Tapo P316M** (a 6-outlet WiFi-controlled power strip, Matter-certified over
WiFi, no Thread) to replace it, expecting the existing `python-kasa` Python
package (or a small protocol port, the way the HS100 driver itself is a
~50-line vendored reimplementation of TP-Link's *legacy* pre-2021 protocol)
would cover it.

It doesn't, and the investigation that found out why is the reason this
protocol needs a fresh implementation rather than an existing library:

- The P316M was confirmed reachable on the LAN and queried directly with
  `python-kasa` (v0.11.0.1, the current, most actively maintained
  implementation of TP-Link's local protocols). It identified the device
  correctly (`Device Type: SMART.TAPOPLUG`, `Device Model: P316M(US)`) but
  refused to connect: `Encrypt Type: TPAP` is not supported.
- TPAP is confirmed as a **newer protocol generation than KLAP**, rolled out
  to some devices via firmware update. This is a real, currently open,
  unassigned gap: [python-kasa#1590](https://github.com/python-kasa/python-kasa/issues/1590),
  filed October 2025, no fix.
- Three independent permissively-licensed KLAP implementations were checked
  (`python-kasa`, `kasa-rs` [MIT], `tapogo` [Apache-2.0]) — **none** of them
  implement TPAP. They would not help against this device.
- A Tapo-app setting ("Third-Party Compatibility" toggle) is rumored in
  community threads to sometimes force a device back into KLAP-compatible
  mode. **Explicitly rejected as a basis for this work** — it is
  undocumented, unconfirmed, and could silently revert on a future firmware
  update, which is exactly the kind of unreliability this project exists to
  get away from (the whole reason the HS100 was being replaced).
- One genuinely working TPAP reference was found and verified:
  **[`KasaTapoClient`](https://github.com/oznetmaster/KasaTapoClient)**
  (.NET/C#, **MIT licensed**, actively maintained — 85 commits, activity as
  recent as this month). Its own README states it's "the only known working
  implementation... of the TPAP protocol path." Its core transport file,
  [`KasaClient/Internal/TpapTransport.cs`](https://github.com/oznetmaster/KasaTapoClient/blob/main/KasaClient/Internal/TpapTransport.cs),
  is **this project's primary reference** — read it carefully; there is no
  written protocol spec, so the C# source *is* the spec. There is no second
  independent implementation to cross-check against, which raises the bar on
  getting this right the first time (write tests, and where possible record
  real wire traffic from a live device to assert against).
- A Matter/Thread-based approach was also evaluated and rejected: the
  P316M's Matter support is real, but the Python Matter tooling ecosystem's
  one mature option (`python-matter-server`) was archived in June 2026 in
  favor of a **Node.js** successor (`matterjs-server`, still beta, not yet
  CSA-recertified); the official Matter/CHIP SDK's Python bindings are
  ctypes wrappers around a massive native C++ framework, not a small
  library. Going this route would trade "port ~2000 lines of one proprietary
  protocol" for "integrate a much larger, currently-in-flux, cross-language
  ecosystem." Not worth it for this scope.
- Why **Rust**, and why a **standalone server process** rather than a Python
  port or a C#/.NET wrapper: see §2.

This repo's only job is: **talk TPAP to real Tapo hardware reliably, and
expose that over a small HTTP API pyhil's power broker already knows how to
drive.** It should have no pyhil-specific code or dependencies in it at all
— see §6 for exactly where that boundary sits.

## 2. Why Rust, why a standalone process

- **Crypto correctness**: TPAP's handshake uses **SPAKE2+** (a real PAKE
  protocol over elliptic curves — see §4), not simple symmetric crypto. With
  no second reference implementation to cross-check against, hand-rolling
  the EC math from scratch is a real correctness risk. Rust has
  [`pakery-spake2plus`](https://docs.rs/pakery-spake2plus) — dual
  MIT/Apache-2.0, implements the *full* RFC 9383 including the
  confirmation/MAC step, actively maintained (v0.6.0, September 2026) — plus
  the mature RustCrypto crate family for everything else TPAP needs (AES-CCM,
  HKDF, HMAC, SHA family, the P-256/P-384/P-521 curves). Building on audited
  primitives instead of hand-rolled ones is the whole point.
- **No FFI boundary, no new runtime burden on pyhil's side.** The
  alternative considered was a thin Python wrapper over this crypto via
  PyO3 (embedding Rust inside the Python process). That was rejected in
  favor of this shape: pyhil's existing `power_servers` architecture already
  runs every controller type as an **independent OS process**, reached by
  the broker purely over HTTP — the broker has never cared what language is
  on the other side of that boundary, it only spawns `[sys.executable, '-m',
  <module>]` today because every existing type happens to be Python. A
  standalone Rust binary is a cleaner fit for that existing design than
  embedding Rust inside a Python process would have been: no FFI anywhere,
  and the deployment story matches an already-established precedent (see
  §7).
- **License**: this repo must be MIT or Apache-2.0 (dual, matching Rust
  ecosystem convention and `pakery-spake2plus` itself) — **not GPL**. (GPL
  was investigated and was not actually the blocker it first appeared to be
  — pyhil already ships an optional GPLv2 dependency, `ppk2-api` — but there
  was no reason to introduce the question at all once a clean path existed,
  and a Rust implementation needs no external GPL crate anyway.)

## 3. Target hardware (what to actually test against)

- **Model**: TP-Link Tapo **P316M** — 6 individually-switchable AC outlets
  (15A/1875W total), 3 always-on USB-A ports (not independently switchable
  — out of scope, see §9). Matter-certified over WiFi; no Thread.
- Confirmed on the development network at discovery time: IP
  `192.168.1.213`, MAC `58-D8-12-66-B9-EC`, hostname `P316M.lan`. **This IP
  is not stable or guaranteed** — treat it as a convenience for your own
  manual testing, not a hardcoded target. The server must take the device's
  address as configuration (§8).
- `python-kasa`'s own discovery (UDP broadcast, port 9999, legacy discovery
  reply format) still identifies this device correctly even though it can't
  connect to it — `kasa discover` or `kasa --host <ip>` is a convenient way
  to re-locate it and confirm its reported `Encrypt Type`/`Login version` on
  any given bench, without needing this server built yet.
- Authentication needs the TP-Link **account** email/password that was used
  to set the plug up in the Tapo app. This is confirmed (independently, by
  both `python-kasa`'s own docs and `KasaTapoClient`'s README) to
  authenticate the **local** TPAP session only — not an ongoing cloud
  dependency. Treat these as sensitive bench configuration (§8), never log
  them, never commit them.

## 4. Protocol summary (TPAP)

Derived from reading `KasaTapoClient`'s `TpapTransport.cs` directly — treat
that file as the actual spec; this is an index into it, not a replacement
for reading it.

**Handshake** (minimum 3 HTTP round trips to `POST /` on the device, plain
HTTP port 80, unencrypted until the session key is established):

1. `login/discover` — unencrypted, returns device capabilities (the
   passcode type the device expects — see candidate credentials below).
2. `login/pake_register` — unencrypted, client sends its SPAKE2+ share;
   device replies with its own random value, a salt, and its share.
3. `login/pake_share` — unencrypted, client sends its SPAKE2+ confirmation;
   device confirms. This establishes the session.

With retry: up to 3 attempts per **candidate credential** (the real device
fleet isn't consistent about which password-derivation scheme a given
model/firmware expects — `TpapTransport.cs`'s `GetCandidateSecrets`/
`ResolveCredentialsString`/`BuildCredentials`/`MacPassFromDeviceMac` cover
MD5/SHA256/plaintext variants, MAC-derived default passcodes, and
shadow/authkey/salt-based transforms), so realistically 3-9 round trips.

**Cryptographic primitives** (map these to Rust crates — see §5):

| Purpose | Primitive |
|---|---|
| PAKE / key agreement | **SPAKE2+** over secp256r1, secp384r1, or secp521r1 (device-negotiated) |
| Key derivation | HKDF-SHA256 or HKDF-SHA512 (cipher-suite dependent) |
| Password-based derivation | PBKDF2-SHA256 |
| Message authentication | HMAC-SHA256/512, AES-CMAC (SPAKE2+ confirmation) |
| Hashing (credential candidates) | MD5, SHA1, SHA256 (yes, MD5 — only for deriving one *candidate* legacy-style credential hash to try, never for anything security-critical) |
| Payload encryption | **AES-128-CCM or AES-256-CCM** (cipher-suite dependent — not CBC, that's KLAP) |
| Encoding | Base64, hex, UTF-8 |
| RNG | A real CSPRNG for all nonces/random seeds — `KasaTapoClient` uses BouncyCastle's; use `rand::rngs::OsRng` or equivalent in Rust |

**Session state** (maintained after the handshake, per connection):

- A session ID / token returned by the device (`TP_SESSIONID`-equivalent;
  check the actual field name in the C# `_sessionId`/`_stok` handling).
- A derived AES key (16 or 32 bytes depending on negotiated cipher suite).
- A base nonce (12 bytes) combined with a monotonically incrementing
  **sequence number** per encrypted request (`NonceFromBase` in the
  reference) — getting this wrong silently produces undecryptable responses
  or the device rejecting requests, so test it explicitly.
- Negotiated cipher ID (`"aes_128_ccm"` / `"aes_256_ccm"`) and HKDF hash
  (`"SHA256"`/`"SHA512"`) — both are per-device/negotiated, don't hardcode
  one.
- Session expiry: 24 hours, with a keep-alive heartbeat sent periodically to
  avoid letting it lapse during a long-idle bench (`SendKeepAliveIfNeededAsync`
  in the reference).

**Request/response shape once the session is live**: encrypted JSON command
envelopes (`EncryptPayload`/`DecryptPayloadEnvelope` in the reference) —
the actual device commands you need are simple (`SMART.TAPOPLUG`'s
get/set-device-info and outlet on/off for a specific child — see
`KasaCommands`/`KasaDevice.Children.cs`/`KasaDevice.Actions.cs` in the
reference repo for the exact command method names and child-addressing
shape for a multi-outlet device).

## 5. Recommended Rust crates

Starting point — verify current versions/maintenance status yourself before
pinning, this is a snapshot from investigation, not a guarantee:

- [`pakery-spake2plus`](https://crates.io/crates/pakery-spake2plus) — RFC
  9383 SPAKE2+, MIT/Apache-2.0. The crate family also includes
  `pakery-crypto` (shared primitives) and `pakery-spake2` (the base
  protocol, RFC 9382 — not what you want, TPAP needs the "+" variant).
- `aes-gcm` / `ccm` (RustCrypto) — AES-CCM.
- `sha1`, `sha2`, `md-5`, `hmac`, `hkdf`, `pbkdf2`, `cmac` (RustCrypto) — the
  hash/MAC/KDF family.
- `p256`, `p384`, `p521` (RustCrypto) — the three SPAKE2+ curve options;
  confirm which one(s) the P316M actually negotiates before assuming you
  only need one.
- `reqwest` or `hyper` (client) — the outbound HTTP calls to the device
  itself (TPAP rides over plain HTTP on device port 80, with the payload
  itself encrypted — not TLS).
- `axum` or `actix-web` — the inbound HTTP server this binary exposes to
  pyhil's broker (see §6). `axum` is a reasonable default (tokio-based,
  matches an async `reqwest` client cleanly) unless you have a reason to
  prefer otherwise.
- `tokio` — async runtime, if using `axum`/`reqwest`'s async variants.
- `serde` / `serde_json` — JSON on both the device-facing and
  broker-facing sides.
- `clap` — CLI argument parsing (host/port/credentials-file flags, see §8).
- `rand` (`OsRng`) — CSPRNG for handshake randomness.

## 6. The HTTP interface this server MUST implement

This is the exact, current contract pyhil's existing power servers speak —
copied directly from the real source
(`pyhil/power_servers/_server_base.py` and
`pyhil/power_servers/kasa_hs100_server.py` in
`ConnectedDevelopment/xtg-generic-linux-test-framework`), not paraphrased.
**Match it precisely** — the broker that will eventually talk to this
server expects these exact routes, JSON shapes, and status-code rules so it
can treat this type exactly like every other controller type.

### Routes

| Method | Path | Request body/query | Success response | Notes |
|---|---|---|---|---|
| GET | `/health` | — | `{"status": "ok"}`, 200 | **Never** touches the real device — a liveness probe for the process, not the hardware. Always unauthenticated, even if a token is configured. |
| POST | `/turn_on` | JSON `{"port": N}` | `{"result": <driver's return value>}`, 200 | |
| POST | `/turn_off` | JSON `{"port": N}` | `{"result": ...}`, 200 | |
| POST | `/toggle` | JSON `{"port": N}` | `{"result": ...}`, 200 | |
| GET | `/get_state` | query `?port=N` | `{"result": ...}`, 200 | Return value should be a plain representation of on/off state — check an existing driver (e.g. `pyhil/power/kasa_hs100.py`'s `get_state`) for the exact shape other types use, to stay consistent. |
| POST | `/sequence` | JSON `{"port": N, "steps": [{"state": "on"\|"off", "hold_ms": <non-negative number, optional>}, ...]}` | `{"result": {"ok": true, "steps": <count>, "last_result": ...}}`, 200 | Runs the whole step list as **one atomic gesture** — the point of this route (see pyhil's own `AbstractPowerSwitch.sequence()`) is that the connection/session isn't torn down and rebuilt between steps, and no other request can interleave mid-sequence. Since this server holds one persistent authenticated session per device already, this should be natural — just serialize execution (see §6.1) and sleep `hold_ms` between steps when given. |

`port` addresses one of the 6 outlets (0-indexed or 1-indexed — **pick one
and be explicit about it in your own README**; pyhil's broker doesn't care
which, as long as it's consistent and documented, since the broker maps its
own named outlets to whatever index convention this server declares). An
out-of-range port must be rejected the same way as every error below.

### Error shape and status codes

Every route (except `/health`, which cannot fail) returns errors as:

```json
{"error": "<human-readable message>", "error_type": "<ErrorCategory>"}
```

with status chosen by this rule (reimplement
`switch_error_status`/`switch_response` from `_server_base.py` — the
*names* `error_type` values take are yours to choose sensibly in Rust
terms, e.g. `"InvalidArgument"` for a bad port, `"Unsupported"`,
`"DeviceError"` — what matters is the **status code mapping**, which the
broker's own Python code already depends on):

- Caller's mistake (bad/missing `port`, malformed body, out-of-range index)
  → **400**.
- A capability the device genuinely doesn't support → **501**.
- Anything else that went wrong talking to the device (handshake failure,
  timeout, device returned an error) → **500**.
- Otherwise → **200** with the `{"result": ...}` envelope.

### Authentication (optional, bearer token)

Mirror `install_common_routes`'s behavior exactly:

- If a token is configured (see §8), every request **except** `/health`
  must carry `Authorization: Bearer <token>` or get `401
  {"error": "unauthorized"}`.
- Compare the token in **constant time** (not a plain `==`) — a timing
  side-channel on a bearer-token comparison is cheap to avoid and the
  existing Python implementation already does this (`hmac.compare_digest`).
  Rust's `subtle` crate or a manual constant-time compare both work.
- If no token is configured, the server is open (matches existing
  behavior/precedent for a trusted local bench network).

### 6.1 Concurrency / session model

pyhil's existing servers serialize every device-facing call through a
single worker (one request processed at a time per physical device,
regardless of how many HTTP requests arrive concurrently) — this matters
because TPAP's AES-CCM nonce/sequence-number scheme is **not safe for
concurrent use of one session** (interleaved requests would corrupt the
sequence counter). Structure this server so all actual device I/O goes
through a single-threaded/mutex-serialized path per device, even though the
HTTP server itself can accept and queue concurrent connections — this is
exactly the `ControllerWorker` pattern in `_server_base.py`'s `Python`
version; you don't need to copy it exactly, just preserve the guarantee
("never two concurrent in-flight requests to the device's actual session").

### 6.2 What this server does NOT need to do

- No multi-device support in one process — pyhil spawns one server process
  per physical device, same as every existing controller type (the device's
  address/credentials are fixed at startup via CLI args, not per-request).
- No `/get_voltage`/`/get_current`/`/set_source_voltage` metering routes —
  out of scope for v1 (see §9), even though the P316M does support energy
  monitoring.
- No pyhil-specific code, imports, or dependencies anywhere in this repo.
  The integration point is the HTTP contract above, nothing else. (The
  pyhil-side change needed to actually spawn this binary — extending its
  `ServerType` registry to support a non-Python command, since it currently
  assumes every controller type is `python -m <module>` — is tracked
  **separately**, in the pyhil repo itself, not here.)

## 7. Deployment / distribution

Match the precedent already established for `hil_led_observer` (another
optional pyhil bench-hardware dependency, same consuming project): ship
**compiled release binaries attached to GitHub Releases** on this repo, not
a package registry. A static or near-static Linux x86-64 binary is the
primary target (match pyhil's bench hosts — Ubuntu); add other
targets/architectures only if/when an actual bench needs them.

This is arguably simpler than the Python-wheel precedent it's following:
there's no interpreter-version-floor compatibility matrix to track (that
was the one real wrinkle `hil_led_observer` hit) — a static binary just
needs a matching OS/architecture.

## 8. Configuration

CLI flags, matching the shape every existing pyhil power server already
uses (`add_common_arguments`/`resolve_token` in `_server_base.py`) so a
human operator or pyhil's own systemd-unit-rendering installer finds this
server unsurprising:

- `--host` (bind address, default `0.0.0.0`) / `--port` (listen port —
  **pick an unused one**; existing servers each claim a distinct port in
  the 5000s, e.g. kasa_hs100 uses 5006 — check
  `pyhil/power_servers/*_server.py` for what's taken before picking one, or
  leave this entirely to pyhil's side to assign at integration time).
- `--token-env <ENVVAR>` — name of an environment variable holding the
  bearer token to require (optional; unset = no auth, matching existing
  convention).
- Device target: an explicit `--host <device-ip>` (or similar) — **do not**
  implement broadcast discovery as the primary path; TPAP devices are
  usually addressed by a known static/DHCP-reserved IP on a bench, and
  discovery adds complexity (and another thing that can flake) this project
  doesn't need yet. A `--discover` convenience mode is fine as a stretch
  goal, not a requirement.
- Credentials: **never accept the TP-Link account password as a bare CLI
  argument** (visible in `ps`, shell history, process listings). Read it
  from an environment variable (e.g. `--password-env TAPO_PASSWORD`,
  mirroring `--token-env`'s own shape) or a credentials file passed by
  path, never logged, never included in error messages that might get
  captured in bench logs.

## 9. Explicitly out of scope for v1

- Energy/power monitoring (`/get_voltage`, `/get_current`) — the P316M
  supports it, pyhil's broker interface has a `meter` capability for it,
  but it's not needed to replace the HS100's basic on/off/toggle role. A
  good v2 addition once the core protocol is solid.
- KLAP support — covered already by `python-kasa`/`kasa-rs` for any device
  that still speaks it; this project exists specifically for the TPAP gap.
  (If it falls out naturally from how you structure the cipher-suite
  negotiation, fine, but don't spend effort chasing it.)
- Matter/Thread control — investigated and rejected, see §1.
- Any device type other than the Tapo power-strip family this was built
  for. Don't generalize prematurely to bulbs/cameras/hubs/etc.
- The Tapo-app "Third-Party Compatibility" toggle or any other
  app-state-dependent behavior — this project must work regardless of that
  setting, not depend on it being in one state.

## 10. Testing expectations

- Unit test the crypto/protocol-state-machine logic independent of a real
  device wherever possible (known-answer tests for the KDF chain, a
  recorded/replayed handshake transcript if you can capture one from a real
  session, matching how `KasaTapoClient` itself has an NUnit test project
  to reference for what "known good" looks like).
- A real-hardware integration test suite, gated behind an explicit
  env var or feature flag (don't run it by default in CI — there's no real
  device available there), is expected and valuable given there's no second
  reference implementation to validate against otherwise. Document how to
  point it at a real device in this repo's own README.
- Test the sequence number / nonce handling explicitly — this is the kind
  of subtle state-machine detail that silently corrupts rather than loudly
  failing when wrong.

## 11. Open questions to resolve during implementation (not blocking the start)

- Exact field names/JSON keys for session ID, sequence counter, and the
  outlet-addressing scheme for a multi-child device — read
  `KasaDevice.Children.cs` and `KasaDevice.Actions.cs` in the reference repo
  closely; this document summarizes from secondary analysis of that file,
  not a line-by-line transcription.
- Which SPAKE2+ curve(s) the P316M specifically negotiates in practice (the
  protocol supports three; confirm empirically against the real device
  rather than assuming one).
- Exact port-indexing convention to settle on for the 6 outlets (0-5 vs
  1-6) — pick one, document it clearly in this repo's own README once
  decided, since pyhil's side will need to know it.
