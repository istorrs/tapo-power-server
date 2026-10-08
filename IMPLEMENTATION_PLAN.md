# Implementation plan

See DESIGN.md (especially §12) for decisions and protocol details.

## M0 - Live probe (done)
Read-only `login/discover` against the P316M. Result recorded in DESIGN §12.

## M1 - Crypto core (no network) [done]
- Cargo project, MIT OR Apache-2.0, pinned RustCrypto 0.11-0.14 generation
  (`p256`, `sha2`, `hmac`, `hkdf`, `pbkdf2`, `aes`, `ccm`, `subtle`, `zeroize`).
  Check `cargo tree -d` for duplicate digest/rand_core generations.
- SPAKE2+ on P-256 with the TPAP transcript (incl. the `w0enc` quirk),
  confirmation MACs, key schedule, CCM framing and sequence handling.
- Tests: RFC 9383 arithmetic sanity vectors, deterministic-scalar seam,
  nonce/sequence unit tests, golden vectors captured from a real session.

## M2 - Handshake and session over HTTP [done, verified on hardware]
- discover / pake_register / pake_share, `dac_nonce`, `/stok=.../ds` transport.
- Credential strategies: `userpw` from `extra_crypt` variants using account
  credentials from env var or file. Lockout guard: no retry loops on auth errors.
- Keep-alive and single re-handshake on retryable errors.

## M3 - Device commands (against real hardware) [done, verified on hardware]
- `get_device_info`, `get_child_device_list`, `control_child` on/off.
- Confirm field names and the DAC behaviour. Only switch outlets 2-5.

## M4 - HTTP server (pyhil contract, DESIGN §6) [done, verified on hardware]
- Axum routes, 400/501/500 mapping, bearer token with constant-time compare,
  `/health` unauthenticated and device-free, `/sequence` atomic.
- One serialised worker owns the session; ports are 1-based (1-6).

## M5 - Hardening and release [done (CI and release workflows are untested until pushed)]
- Hardware tests behind an env var, outlet allowlist 2-5, documented in README.
- CI, musl static build (`rustup target add x86_64-unknown-linux-musl`),
  GitHub Release workflow.
