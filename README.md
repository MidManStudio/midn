# Midn Core

> Experimental LTE/5G Core Network — Rust

An experimental, from-scratch implementation of a 3GPP mobile core network.
Not production-ready. Not feature-complete. Built to understand what a
data-oriented, zero-copy cellular core actually looks like when you stop
accepting the assumptions of legacy stacks.

## What it is

A private LTE/5G core network with:

- **Milenage/TUAK** — 3GPP AKA authentication against real SIM cards
- **NAS / S1AP / NGAP** — control plane protocol parsers, PER codecs, and state machines
- **MME / AMF** — subscriber session lifecycle backed by an ECS registry (`midn-ecs`)
- **AMF Registration** — full 5G-AKA registration flow: Phase A (DownlinkNasTransport) and Phase B (InitialContextSetupRequest with a bundled default PDU session)
- **SCTP transport** — `midn-transport`, Sans-IO SCTP-over-UDP (via `rtc-sctp`), confirmed working end-to-end over a real socket
- **midn-sim** — a two-process simulation binary (AMF + mock UE/gNB) proving the stack talks to itself over a real socket boundary, no shared in-process state
- **GTP-U** — zero-copy user plane tunnel parser
- **eBPF / XDP** — kernel-level packet steering (Phase 3)

## What it is not

- Production-ready
- A full 3GPP compliance suite
- A drop-in replacement for OpenAirInterface or free5GC
- Real IP-layer SCTP interop — `midn-transport` runs SCTP over UDP by design (no `IPPROTO_SCTP`), which works everywhere (CI, no local toolchain, real hardware) but isn't wire-compatible with real gNB/AMF equipment yet
- Stable API (everything changes until v1.0)

## Crates

| Crate | Role | Phase |
|---|---|---|
| `midn-auth` | Milenage / TUAK SIM authentication | 1 |
| `midn-proto` | NAS, S1AP, NGAP, GTP-U — parsers and PER codecs | 2 |
| `midn-ecs` | Data-oriented entity/component registry backing subscriber state | 2 |
| `midn-core` | MME/AMF state machines — registration, default bearer / PDU session setup | 2 |
| `midn-transport` | Sans-IO SCTP-over-UDP transport (`rtc-sctp`) | 2 |
| `midn-sim` | End-to-end simulation binary — AMF + mock UE/gNB over a real socket | 2 |
| `midn-userplane` | UPF routing + eBPF loader (Linux) | 3 |
| `midn-userplane-ebpf` | Kernel XDP program — no_std | 3 |

## Quick Start

```bash
# Phase 1: authentication only
cargo build -p midn-auth
cargo test  -p midn-auth

# Phase 2: protocol stack + control plane
cargo build -p midn-proto
cargo test  -p midn-proto
cargo build -p midn-core
cargo test  -p midn-core

# Phase 2: transport + end-to-end simulation
cargo test -p midn-transport   # offline handshake test, no real socket
cargo run  -p midn-sim         # live AMF + UE registration over SCTP-over-UDP

# Benchmarks (release numbers only — debug is meaningless for perf)
cargo bench -p midn-auth
cargo bench -p midn-proto
```

## mid-math dependency

Signal geometry and handover calculations use `mid-math`. Pick one option
in the root `Cargo.toml` and uncomment it:

```toml
# Git (CI-friendly)
# mid-math = { git = "https://github.com/Mid-D-Man/mid-engine", branch = "main" }

# Local path (mid-engine checked out alongside midn-core)
# mid-math = { path = "../mid-engine/crates/mid-math" }
```

## Performance Targets

| Subsystem | Target | Measured by |
|---|---|---|
| Milenage auth vector | < 10 µs | `cargo bench -p midn-auth` |
| GTP-U header parse | < 500 ns | `cargo bench -p midn-proto` |
| ECS subscriber spawn | < 1 µs | unit tests |
| Concurrent sessions | 100k+ | stress tests |
| XDP packet decision | < 200 ns (Phase 3) | kernel perf counters |

## CI

Tests and benchmarks run on GitHub Actions.

| Workflow | Trigger | What runs |
|---|---|---|
| `midn-test.yml` | Push/PR to `main`/`master`/`develop` (path-gated per crate via commit tokens `--midn-auth`, `--midn-proto`, `--midn-ecs`, `--midn-core`, `--midn-userplane`, `--midn-all`), or manual | Per-crate unit tests. Manual dispatch always runs all crates. `midn-transport` and `midn-sim` are **not yet** wired into this path-gated system. |
| `midn-bench.yml` | Manual only (Actions → "midn-core: Benchmarks") | Criterion benchmarks against the targets above |
| `midn-sim-smoke-test.yml` | Manual only | Runs `midn-transport` + `midn-sim` for real — a live AMF + UE registration over an actual SCTP-over-UDP socket, with a pass/fail checklist written to the job summary |

`midn-userplane`'s eBPF feature build runs as part of `midn-test.yml` whenever `midn-userplane` is triggered (`continue-on-error: true` — verifier issues don't block the gate).

## Docs

Deeper design notes live under [`docs/`](docs/): `architecture.md`, `dev-setup.md`, `phase1-auth.md`, `phase2-proto.md`, `phase3-userplane.md`, `platform-optimization.md`.

## eBPF (Phase 3, Linux ≥ 5.8 only)

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

cargo +nightly build -p midn-userplane-ebpf \
  --release --target bpfel-unknown-none -Z build-std=core
```

## License

Proprietary — All Rights Reserved. See [LICENSE.md](LICENSE.md). No license,
express or implied, is granted by this repository being public.
