# Node Runner

A desktop orchestrator for a compute node that migrates itself between GitHub
Actions runners every 5 hours 40 minutes, keeps a stable public hostname across
every migration, and stores its credentials in a local encrypted vault rather
than in plaintext configuration.

Three parts:

| Part | What it is | Where |
| --- | --- | --- |
| **Vault** | Rust library: Argon2id + AES-256-GCM + DPAPI + HMAC, with page-locked, zeroizing buffers | `desktop/nrvault/` |
| **App** | Tauri v2 desktop controller: node status, countdown, tunnel endpoint, ledger, kill switch | `desktop/src-tauri/`, `desktop/src/` |
| **Node** | The lifecycle that runs on the runner: restore, serve, freeze, snapshot, hand over | `runner/`, `.github/workflows/runner.yml` |

Start with [`docs/SETUP.md`](docs/SETUP.md). Read
[`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) before you run this against a real
GitHub account, and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before you
trust it with real data.

## What one cycle looks like

```
   watchdog (cron, */30)          node (workflow_dispatch, 360 min ceiling)
        |                              |
        |  heartbeat is stale?         |
        +----------------------------->|
                                       |
   t+0     preflight ....... tools, credentials, Drive reachable
   t+1     lease ........... acquire the single-writer lease
   t+2     restore ......... newest committed snapshot, verified by manifest
   t+6     ack ............. predecessor may now stop (state exists twice)
   t+8     serve ........... tunnel connector up, workload started
   t+325   freeze .......... SIGSTOP workload, wait for dirty pages, sync
   t+327   backup .......... hash, upload, verify, commit, prune old snapshots
   t+329   handover ........ dispatch successor, wait for its ack
   t+334   drain ........... stop workload and tunnel, scrub, release lease
                                       |
                                       +--> successor run starts (slot ping-pong)
```

The interval between "predecessor stops" and "successor serves" is the reason the
successor is dispatched *while the predecessor is still alive*. GitHub's ceiling
is per job, so the successor has to spend some of its own budget on startup
during the predecessor's last minutes; that overlap is bought with about ten
minutes of the successor's 340, and it is what keeps the endpoint continuously
bound.

## Two deliberate departures from the original specification

Both are explained where they live in the code, because a reader who finds one of
them should not have to guess whether it was intentional.

**1. Handover is a self-dispatch inside one repository, not a new repository every
cycle** (`runner/lib/handover.sh`). Creating a fresh public repository every 5h40m
and injecting a repo-creating PAT, a Drive service-account key and a tunnel token
into it concentrates the operator's most privileged credential in a
world-readable secret store, repeatedly, forever — and using Actions as perpetual
general-purpose compute via self-replicating repositories is the pattern GitHub's
Acceptable Use Policies exist to stop, with account suspension as the failure
mode. One private repository with the secrets configured once achieves the same
migration, and the PAT needs `actions:write` on one repository instead of account
scope. See `docs/COMPLIANCE.md`.

**2. Snapshots are immutable and additive, not `rclone sync` to a mutable path**
(`runner/lib/backup.sh`). `sync` makes the destination match the source
*including deletions*, so a workload that loses files would propagate that loss
into the only durable copy, and then into the next node's restore, and then it is
gone. Each cycle writes `snapshots/<timestamp>/` with `rclone copy`, verifies it
against a manifest, and only then publishes a commit record. The previous
snapshot stays as the fallback until the successor acknowledges the new one.

## What is verified, and what is not

Verified on this machine:

* `cargo test -p nrvault` — **53 tests passing**, including the DPAPI path
  executing against the real Windows API, tamper detection, wrong-passphrase
  handling, and libsodium-compatible sealed-box output. See
  [`docs/SECURITY.md`](docs/SECURITY.md#test-inventory).
* `npx tsc --noEmit` — clean under `strict`, `noUncheckedIndexedAccess`, and
  `exactOptionalPropertyTypes`.
* `npx vite build` — 27.1 KB JavaScript, 7.6 KB CSS, zero runtime dependencies.
* `bash -n` over every runner script; both workflows parse.

**Not verified here, and this matters:** the Tauri application was never compiled.
This machine has no working linker for either `windows-msvc` (no `link.exe`) or
`windows-gnu` (the bundled `dlltool` needs an assembler the toolchain does not
ship), so `desktop/src-tauri/` is unbuilt and unrun. The first real build is
[`.github/workflows/desktop-ci.yml`](.github/workflows/desktop-ci.yml), which
builds it on `windows-latest`, runs the size gate, and uploads the executable.
Expect to fix compile errors there on the first run rather than finding a
verified binary in this repository.

Two specification claims are also corrected rather than reproduced:

* `CryptProtectData` is bound to the **Windows user profile**, not the TPM. Real
  TPM binding requires CNG/NCrypt with the Platform Crypto Provider, which the
  vault exposes as a feature for the key-wrap backend and does not yet implement.
* `zeroize` scrubs memory on drop but does **not** prevent pages from being
  written to swap. That is `VirtualLock`, and it is implemented and reported in
  the UI as a distinct fact from "the vault is encrypted".
