# Threat model

Structured as: what is worth stealing, who would try, what stops them, and what
is left over. The "what is left over" sections are the point of the document.

## Assets

| Asset | Where it lives | If it leaks |
| --- | --- | --- |
| **GitHub PAT** | Local vault (encrypted); runner environment | `actions:write` + `secrets:write` on one repository. An attacker can read and rewrite the node's secrets and start runs — a foothold on your GitHub account, not a takeover of it. |
| **Drive service-account key** | Local vault (encrypted); runner environment | Read/write on the backup folder. Read-and-write means the attacker can *delete* the backups, which is the worst-case outcome in this system. |
| **Tunnel token** | Local vault (encrypted); runner environment; the connector's `argv` | Someone else can connect a connector to your hostname. Scoped to one tunnel. |
| **Snapshot contents** | Google Drive (plaintext), runner filesystem | Whatever the workload handles. **Not encrypted by this system** — see residual risk 1. |
| **Vault master passphrase** | The operator's head | Everything local. Not stored anywhere by design. |

## Adversaries

### 1. Offline disk theft (laptop stolen, drive imaged)

*Stops it:* the vault is AES-256-GCM under an Argon2id-derived key with a random
per-installation salt, and the file is HMAC'd end to end. Without the passphrase
there is no offline attack better than guessing, at a calibrated ~250 ms per
guess. The DPAPI copy of the DEK is useless on another machine and under another
user profile.

*Residual:* an attacker who guesses the passphrase gets everything, so passphrase
entropy is the whole control. The vault enforces a minimum length at creation and
nothing more; a long passphrase is a real requirement, not a suggestion.

### 2. Another user on the same machine

*Stops it:* the vault file is per-user, DPAPI binds the DEK copy to the user's
logon credentials, `zeroize` clears payload buffers on drop, and `VirtualLock`
keeps those pages out of the pagefile.

*Residual:* ACLs on `%APPDATA%` are the actual boundary, and the app does not
strengthen them beyond the OS default. On a shared machine, treat the vault as
protected by "different user account" and nothing more.

### 3. Malware running as you, vault unlocked

*Stops it:* nothing. This is stated plainly because pretending otherwise is the
most common way a security design misleads its user. Code running as you can read
the process's memory, call the same IPC surface the UI calls, and use the DPAPI
wrap to decrypt the DEK without knowing the passphrase. That last property is the
price of convenience unlock, and it is a real reduction in security relative to
passphrase-only.

*Mitigations that reduce the window:* auto-lock on idle, lock on tray click, lock
before quitting, and the option to run without the DPAPI wrap at all (seal with
`os_wrap` disabled; then the passphrase is required every time and the vault is
unreadable to a process that cannot keylog you).

### 4. Malware running as you, vault locked

*Stops it:* there is no DEK in memory and no plaintext anywhere on disk. The
remaining attack is to wait for the unlock, or to keylog the passphrase — which is
adversary 3 with extra patience.

### 5. Compromised runner (the interesting one)

A runner holds the Drive key, the PAT, the tunnel token and the decrypted
snapshot, in memory, for hours, on a machine that runs your workload's code.

*Contained by:*
* **Narrow credentials.** The PAT has `actions:write` and `secrets:write` on one
  repository — no `Administration`, so it cannot create repositories or delete
  the repository it lives in. The original specification's design required
  repository-creation authority and copied that token into a fresh public repo
  every cycle; that is not implemented, see [COMPLIANCE.md](COMPLIANCE.md).
* **Immutable history.** Snapshots are additive. A compromised node can write a
  poisoned new snapshot, but it cannot destroy the previous one — and the
  successor will not commit a snapshot whose manifest does not verify. It *can*
  still commit a well-formed snapshot containing bad data, because a manifest
  proves integrity, not honesty.
* **A bounded lifetime.** The host is destroyed at the end of the job, and the
  next node gets a new one. Compromise is not permanent residence.
* **Ephemeral exposure of the config.** The service-account key is written to a
  temp file with mode 0600 only because rclone requires a path, and is shredded
  before the lease is released.

*Residual:* the DRIVE key's blast radius is the backup folder, and an attacker
with it can delete every snapshot. **This is the single most damaging possible
outcome.** Two things limit it and neither eliminates it: the operator's own
machine can keep a copy of the newest snapshot (not implemented — a real
recommendation), and a Drive folder can be configured with versioning and
retention through Workspace policy, which is outside this code.

### 6. Malicious or buggy successor

*Stops it:* the successor cannot fabricate an acknowledgement — the predecessor
only accepts an ACK keyed to the commit it published, and only publishes after
`rclone check` verifies the upload. A successor that restores a *previous*
snapshot is possible (it is the fallback path) and is detected through the
commit-record chain, where each record names its parent.

*Residual:* a successor running bad workload code is indistinguishable from a
workload bug. The system preserves state; it does not validate what the workload
does with it.

### 7. Network attacker

*Stops it:* everything in transit is TLS and authenticated — GitHub over TLS with
a bearer token, Drive over TLS with a signed JWT, Cloudflare over QUIC with a
tunnel secret. Snapshot verification uses hashes computed by the producer, so a
manipulating proxy would have to break TLS *and* produce a matching manifest.

*Residual:* nothing here pins certificates or detects a compromised CA. That is
accepted; the marginal value over the OS trust store is low for this workload.

### 8. Accidental destruction by the operator

The most likely incident is not an attacker. It is someone deleting the wrong
thing, letting the PAT expire mid-flight, or bumping `RCLONE_VERSION` without
re-recording the checksum and breaking every future cycle at the install step.

*Contained by:* the kill switch (a graceful stop rather than a hard one), the
retention window (20 snapshots ≈ 4 days of cycles, so an unnoticed problem is
still recoverable), backups of the vault, and the setup documentation being
explicit about what a version bump invalidates.

*Residual:* there is no tested restore-from-scratch drill. Practise it once
before you need it — [OPERATIONS.md](OPERATIONS.md#restore-drill) has the
procedure.

## Non-goals

1. **Encrypting the snapshot.** Drive sees plaintext. If the workload handles
   sensitive data, encrypt inside the workload or use a client-side-encrypted
   remote; this system does not do it for you.
2. **TPM binding.** Advertised as a trait, not implemented. DPAPI here is
   user-profile-bound.
3. **Protecting against a hostile GitHub or Google.** Both are trusted
   infrastructure in this design.
4. **Availability guarantees.** The handover keeps the endpoint bound across
   normal cycles. It does not make GitHub's scheduler reliable, and a runner
   outage will take the node down until the watchdog recovers it.
5. **Hiding that the node exists.** The tunnel hostname, the repository, its run
   history and its size are all publicly inferable in many configurations.
