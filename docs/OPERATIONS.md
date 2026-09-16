# Operations

## Day-to-day

Nothing. The node migrates on its own, the watchdog restarts it if it dies without
handing over, and the desktop app is read-only telemetry plus a kill switch.

What is worth checking occasionally:

* **The ledger.** A cycle that shows `committed` with the expected file count and
  a parent that is the previous commit means the chain is healthy. A cycle showing
  `failed` or a commit with an unexpected parent means something interrupted.
* **The heartbeat age on the dashboard.** Under 2 minutes during a cycle, up to
  about 40 minutes around a large snapshot. Beyond that, the watchdog is about to
  intervene.
* **The `node` workflow's scheduled runs are still enabled** (Actions tab).
  GitHub disables schedules in a repository with no activity for 60 days, and this
  loop never pushes a commit. See [SETUP.md](SETUP.md#4-start-the-loop).

## Controls

### Kill switch

The app writes `KILLSWITCH.json` to the Drive folder. The node reads it:

* every few minutes during the runtime gate, and
* once more immediately before the handover.

Engaging it stops the current node **gracefully**: the workload is still frozen
and snapshotted, the snapshot is still committed, and no successor is dispatched.
State is preserved; the loop simply ends. That is deliberate — a "stop" that lost
the last cycle's work would be a stop nobody dares use.

Clearing it does not restart the loop. Dispatch a node manually when you are ready.

### Force migration / failover

The dashboard's failover action dispatches a node with reason `failover` in the
opposite slot, without waiting for the current node to finish. Safe to use at any
time: the lease means either the new node waits for the current one or the current
one is genuinely gone. It is also the right response to a node that is hung in a
way the watchdog has not yet noticed.

### Lock

Tray → **Lock vault** zeroizes the payload and drops the cached Drive token. The
polling stops until you unlock again; the node itself is unaffected.

## Failure playbook

| Symptom | Cause | Action |
| --- | --- | --- |
| Node stuck in `starting` for a long time | `rclone about` failing: folder not shared with the service account, or the Drive API not enabled | Check the run log for the preflight error; fix in the Google console |
| `timed out waiting for the lease` | Predecessor died mid-snapshot and its lease has not gone stale yet (900 s) | Wait — the successor breaks a stale lease by itself. Recurring means two nodes are being dispatched by something other than a predecessor |
| `Service Accounts do not have storage quota` | Writing to a personal My Drive folder | Use a Shared Drive or delegation; [SETUP.md](SETUP.md#1b-give-it-somewhere-to-write--and-read-this-part) |
| Node stops with no successor | Handover dispatch failed: PAT expired, or missing `actions:write` | Dispatch manually from the Actions tab, then fix the PAT |
| Watchdog never fires | Scheduled workflow disabled by GitHub, or cron not on the default branch | Re-enable in the Actions tab; confirm the workflow is on the default branch |
| Two nodes running for a long time | A double dispatch | Not corrupting — the lease prevents a torn snapshot. But two workloads writing one tree can disagree, so stop one from the Actions tab |
| Snapshot verification failed on restore | Upload was truncated, or Drive corrupted the object | The successor falls back to the previous commit; the run log names the failing file |

Recovering a *stopped* loop always looks the same: dispatch a node with
`reason=bootstrap` and an empty `commit`. The successor's restore path takes the
newest committed snapshot; if there is none, it starts empty. There is no state to
lose by hand-starting a node — only by deleting snapshots.

## Restore drill

Practise this before you need it. It takes a few minutes and it is the only thing
that proves the backups are real.

```bash
# As the service account, listing what actually exists:
rclone lsf --dirs-only gdrive:snapshots/ | sort | tail -3
rclone cat gdrive:state/COMMIT/$(rclone lsf gdrive:state/COMMIT/ | sort | tail -1)

# Restore the newest committed snapshot into a scratch directory:
SNAP=$(rclone cat gdrive:state/COMMIT/$(rclone lsf gdrive:state/COMMIT/ | sort | tail -1) | jq -r .snapshot)
rclone copy "gdrive:$SNAP" /tmp/drill --transfers 8 --fast-list --exclude '/MANIFEST.sha256'
rclone copyto "gdrive:$SNAP/MANIFEST.sha256" /tmp/drill.MANIFEST.sha256

# Verify exactly what the node verifies:
cd /tmp/drill && sha256sum --quiet -c /tmp/drill.MANIFEST.sha256 && echo "drill OK"
```

If that prints `drill OK`, the restore path is proven end to end. If it does not,
you have found a problem while the node is still running, which is the whole
purpose of the exercise.

## Maintenance

### Bumping a tool version

Both tools are pinned, and both are checksum-verified:

* **rclone** — update `RCLONE_VERSION` in `.github/workflows/runner.yml`. No
  checksum file to update: the archive is verified against the release's own
  `SHA256SUMS`.
* **cloudflared** — update `CLOUDFLARED_VERSION` in the same place **and** the
  digest in `runner/cloudflared.sha256`. Forgetting the second is a hard failure
  at the install step *before* any state is touched, because a checksum
  disagreement or a missing pin is deliberately fatal. The script also
  cross-checks the file against the digest GitHub's release API publishes, so a
  stale or hand-edited pin cannot quietly become a weaker one.

Also update the version comment at the top of `runner/install-tools.sh`, which
records where each value came from and on what date.

### Operational parameters

All overridable from `.github/workflows/runner.yml`:

| Variable | Default | Notes |
| --- | --- | --- |
| `CYCLE_MINUTES` | 340 | Longest job is 360; the scripts refuse to start if this leaves under 15 minutes of margin |
| `FREEZE_AT_MINUTES` | 325 | Must be below `CYCLE_MINUTES`; the scripts refuse to start otherwise |
| `BACKUP_RETENTION` | 20 | Snapshots kept, minimum 2 enforced. At 340-minute cycles this is ≈ 4.7 days |
| `ACK_TIMEOUT_SECONDS` | 180 | How long the predecessor holds the domain waiting for the successor |
| `LEASE_STALE_SECONDS` | 900 | When a successor may break a predecessor's lease |
| `DIRTY_WAIT_SECONDS` | 90 | How long to wait for writeback to settle after freezing |
| `DRAIN_GRACE_SECONDS` | 45 | SIGTERM window before SIGKILL |

Widening the cycle past 340 minutes is a bad idea: 360 is a hard platform ceiling
and a job killed by GitHub mid-snapshot leaves an incomplete snapshot directory
that the next restore must work around. Widen the *retention* instead if you want
deeper history.

## Footprint claims

The specification asked for **under 25 MB idle RAM** and **under 5 MB binary**.
Neither is verified by this repository, and here is the honest position on each.

**Binary size** is gated in CI (`desktop-ci.yml`): over 5 MiB warns, over 10 MiB
fails the build. The build uses `opt-level="z"`, LTO, `panic="abort"`, `strip`
and the OS TLS stack rather than `rustls`. The 5 MiB figure is reachable only with
UPX, which is not used because packed executables are routinely flagged by
endpoint protection — a <5 MB binary that antivirus quarantines is not shipping,
it is hiding. Check the CI summary for the measured size.

**Idle memory** depends on WebView2, which the app does not control, so a CI
measurement would be measuring Microsoft's runtime rather than this code. To
measure it yourself, on a machine with the release build:

```powershell
# Dashboard open (WebView2 hosts resident):
Get-Process node-runner, msedgewebview2 |
  Measure-Object WorkingSet64 -Sum |
  Select-Object @{n='MiB';e={[math]::Round($_.Sum/1MB,1)}}

# Close the dashboard (it is destroyed, not hidden) and wait a few seconds:
Start-Sleep 5
Get-Process node-runner |
  Measure-Object WorkingSet64 -Sum |
  Select-Object @{n='MiB';e={[math]::Round($_.Sum/1MB,1)}}
```

The second number is the one that matters, and it is the reason the window is
destroyed on close rather than hidden: a hidden WebView2 keeps its host processes
resident, and they dominate the total. Expect the backend-only figure to be a
small single-digit number of MB, and the dashboard-open figure to be dominated by
WebView2.
