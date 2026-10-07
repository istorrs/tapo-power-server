# tapo-power-server

A standalone Rust server that speaks TP-Link's TPAP protocol to Tapo
power-strip hardware and exposes it over a small HTTP API, for use as an
optional bench-hardware power controller by
[pyhil](https://github.com/ConnectedDevelopment/xtg-generic-linux-test-framework).

**Start here: [`DESIGN.md`](./DESIGN.md).** It covers why this project
exists, the protocol background, the exact HTTP contract to implement, crate
recommendations, configuration, and what's explicitly out of scope for a
first version. Read it in full before writing code — there is no separate
spec; it's self-contained.

Status: design-stage, no implementation yet.
