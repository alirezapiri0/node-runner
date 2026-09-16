# Security

What the vault does, what it provably does not do, and which of those two things
each control belongs to.

---

## Threat model in one paragraph

The vault protects credentials **at rest and while the app is locked**. It does
not, and cannot, protect them from an attacker who already runs code as you while
you have the vault unlocked — that attacker can read the same memory the app can.
Every control below is aimed at the realistic attacks: a stolen laptop, a backup
that syncs to cloud storage, a curious process on the machine, a misconfigured
sync client, and casual inspection of the configuration directory. The full
adversary breakdown is in [THREAT_MODEL.md](THREAT_MODEL.md).

---

## File format

`vault.nrv` is a single self-describing file. Binary layout:

```text
offset  size  field
     0     8  magic "NRVAULT1"
     8     2  format version (u16 LE)
    10     1  kdf id (1 = Argon2id)
    11     1  aead id (1 = AES-256-GCM, 2 = XChaCha20-Poly1305)
    12     4  memory cost KiB (u32 LE)
    16     4  time cost (u32 LE)
    20     1  parallelism
    21    32  salt
    53    12  nonce for the KEK wrap
    65    24  nonce for the payload
    89     3  flags
    92     4  length of the OS-protected blob (u32 LE)
    96     4  reserved (must be zero)
   100   ...  OS-protected DEK blob        (DPAPI)
    ..    48  DEK wrapped under the KEK    (32 ciphertext + 16 tag)
    ..   ...  payload ciphertext           (plaintext + 16 tag)
    ..    32  HMAC-SHA256 over everything above
```

Key hierarchy:

```text
passphrase --Argon2id(salt, m, t, p)--> IKM --HKDF--> wrap_key, mac_key
wrap_key   --AES-256-GCM------------> wrapped_dek_pass
random DEK --DPAPI------------------> dpapi_blob        (Windows)
DEK        --AEAD(payload, aad)-----> payload_ct
DEK        --HKDF-------------------> file_mac_key
file_mac_key --HMAC-SHA256----------> mac
```

The data encryption key is **random, never derived from the passphrase**. Three
consequences, all of them intentional:

* Passphrase rotation re-wraps 32 bytes; it does not re-encrypt the payload.
* The passphrase path and the DPAPI path are independent. Losing either still
  leaves the other, so the OS path failing degrades to "enter the passphrase"
  rather than "vault lost".
* A fresh DEK per seal keeps the message count per key far below the AEAD's
  birthday bound, so nonce reuse cannot become a practical concern.

The file MAC is keyed **from the DEK**, not from the passphrase. The earlier
design keyed it from the passphrase, which had two real problems: a session that
unlocked via DPAPI could not write at all, and a wrong passphrase and a tampered
file produced the same error — meaning the UI would either cry tamper on a typo or
stay silent on real tampering. Keying from the DEK fixes both, and gives the
DPAPI path genuine integrity checking rather than none.

---

## Controls, and what each one actually buys

### Argon2id (KDF)

Memory-hard, so GPU and ASIC brute force loses its advantage. Parameters are
calibrated on this machine to a ~250 ms target and recorded in the file, so a
vault opens at the cost it was sealed with and can be re-sealed at a higher cost
later. Bounds are enforced on read, so a modified file cannot request a 1 MiB
memory cost (downgrade) or a 4 GiB one (denial of service). Covered by
`kdf_bounds_reject_downgrade_and_bomb`.

### AES-256-GCM / XChaCha20-Poly1305 (AEAD)

Authenticated encryption with a random 12-byte nonce (24 for XChaCha, whose
larger nonce is why it is offered as the alternative). The header is bound as
associated data, so the parameters and identifiers cannot be edited without the
decryption failing. Covered by `nonces_and_deks_are_unique_across_seals`,
`every_truncation_is_safe`, `arbitrary_bytes_never_panic`.

### DPAPI (OS key wrap)

`CryptProtectData` wraps a copy of the DEK under the current Windows user's
credentials, so unlocking does not require retyping the passphrase on this
machine. Two corrections to the original specification:

* **This is user-profile-bound, not TPM-bound.** DPAPI's `CRYPTPROTECT_LOCAL_MACHINE`
  is off, which binds the blob to the user's logon credentials; it does not
  require a TPM and does not attest to hardware. Genuine TPM binding needs
  CNG/NCrypt with `MS_PLATFORM_CRYPTO_PROVIDER`, advertised through the
  `keywrap::TpmBinding` trait, which is **not implemented**. Do not describe this
  vault as TPM-protected.
* The blob is created with optional entropy derived from the vault's own salt, so
  a blob cannot be transplanted between vaults. Covered by
  `os_blob_is_bound_to_its_entropy` and `tampering_with_the_os_blob_is_detected`,
  which run against the real Windows API.

### HMAC-SHA256 (whole-file integrity)

Every byte up to the MAC is covered. This is what detects bit rot and deliberate
edits **before** any decryption is attempted, and it is a separate primitive from
the AEAD on purpose: it protects the fields the AEAD does not, notably the
DPAPI blob and the KDF parameters.

### VirtualLock + zeroize (memory)

* `zeroize` clears secret buffers on drop, so a decrypted payload does not become
  unreachable-but-present heap.
* `VirtualLock` pins those pages so the OS does not write them to `pagefile.sys`
  or to a hibernation file. **`zeroize` does not do this** — the specification
  implied it did; it does not. A zeroized-but-paged page can persist on disk.
* The working-set quota is widened at startup, before any vault work, so the lock
  is not refused under memory pressure. If locking is unavailable, the app says
  so in the Logs tab rather than pretending.

Covered by `locked_buffers_zeroize_and_report_pinning`.

### Atomic writes and backup generations

Writes go to a temporary file, are flushed, and are renamed over the target, so a
crash mid-write leaves the previous vault intact rather than a half-file
(`torn_write_leaves_the_previous_vault_intact`). The previous generation is kept
as a recoverable backup (`backup_generation_is_recoverable`).

### Tamper ledger

A structural failure or an integrity failure is recorded as a strike and surfaced
in the UI, and a mistyped passphrase deliberately does **not** raise one
(`a_mistyped_passphrase_does_not_raise_a_tamper_alarm`). The distinction is made
possible by an envelope fingerprint recorded at seal time: key material cannot
distinguish "wrong passphrase" from "edited header", but a stored fingerprint can.

### Write-only command surface

No Tauri command returns a secret value. The frontend can set, delete, list by
name, fingerprint and rotate, but `vault_list_secrets` returns metadata only.
This is enforced in the command layer rather than in the UI, so a compromised
frontend — or a developer adding a convenience API — does not get a plausible
exfiltration path. The only way a secret leaves the process is
`secrets_inject`, which encrypts it to GitHub's repository public key and sends it
to `api.github.com`; there is no command that will hand it to the webview.

### Dependency-free frontend

`dependencies` in `desktop/package.json` is empty and CI fails if it is not
(`No runtime dependencies`). The frontend is what a compromised UI library would
run inside, in the same process that holds the unlocked session.

---

## The tunnel token, and argv

`cloudflared` accepts its connector token only as a command-line argument, so
`CF_TUNNEL_TOKEN` is visible in `/proc/<pid>/cmdline` on the runner for the life
of the process. Everything else in the system avoids this: the GitHub PAT, the
service-account JSON and the vault payload reach their consumers through the
environment or through stdin (`gh_api` feeds the PAT to `curl --config -` rather
than `-H`, precisely so it never enters `argv`).

Mitigations, in the order they help:

1. The token is scoped to one tunnel and grants no access to Drive, GitHub or the
   account around it.
2. Rotate it from the Cloudflare dashboard if a runner is ever suspect. Rotation
   does not touch the tunnel's hostname, so the endpoint stays stable.
3. The runner host is GitHub's, single-tenant, and destroyed after the job.

---

## Deliberate non-goals

* **Protection from code running as you, while unlocked.** Impossible by
  construction. If that is in your threat model, the vault is the wrong control
  and you need OS-level isolation.
* **Protection from a compromised runner.** The runner holds the Drive key and
  the PAT in memory by necessity. What limits the damage is that both are
  rotateable and narrowly scoped, and that the snapshots are immutable.
* **Hiding metadata.** File size, the number of snapshots, the timing of cycles
  and the commit records are all unencrypted. Only the local vault is encrypted;
  the Drive layout is not.
* **Anti-forensics on the host.** Nothing here protects the runner's disk, which
  is discarded anyway.

---

## Test inventory

`cargo test -p nrvault` — **53 tests, all passing** as of this writing. The
security-relevant ones:

| Area | Tests |
| --- | --- |
| Round trip | `round_trip_payload`, `round_trip_preserves_exact_bytes`, `empty_payload_round_trips` |
| Format | `serialization_is_canonical_and_stable`, `file_layout_matches_the_documented_length` |
| Tamper detection | `tamper_any_region_is_detected`, `swapping_the_whole_payload_between_vaults_is_detected`, `mac_verification_reports_definite_tamper`, `a_wrong_passphrase_and_a_modified_payload_are_distinguishable` |
| Fuzzing | `arbitrary_bytes_never_panic`, `every_truncation_is_safe`, `structural_rejects_are_fast`, `structural_rejection_cases` |
| Key hygiene | `keys_are_separated_by_purpose`, `nonces_and_deks_are_unique_across_seals`, `repeated_writes_never_reuse_a_payload_nonce` |
| KDF policy | `kdf_bounds_reject_downgrade_and_bomb`, `calibration_stays_within_bounds`, `kdf_parameters_are_recorded_and_agile` |
| Rotation | `rotate_passphrase_invalidates_the_old_one`, `rekey_changes_dek`, `rotation_requires_the_passphrase_not_just_an_open_session` |
| On-disk hygiene | `no_plaintext_reaches_disk`, `secrets_are_only_readable_through_the_store`, `destroy_removes_every_artifact` |
| Redaction | `payload_debug_output_is_redacted`, `passphrase_debug_and_display_are_redacted`, `vault_debug_output_is_redacted`, `error_messages_never_contain_secret_material` |
| Memory | `locked_buffers_zeroize_and_report_pinning` |
| DPAPI (real Windows) | `os_protector_round_trip`, `convenience_unlock_without_a_passphrase`, `os_blob_is_bound_to_its_entropy`, `tampering_with_the_os_blob_is_detected` |
| Sealed boxes | `overhead_is_exactly_the_libsodium_sealbytes`, `round_trip_recovers_the_secret`, `sealing_is_nondeterministic`, `only_the_intended_recipient_can_open`, `tampering_with_a_sealed_box_is_rejected`, `malformed_keys_are_rejected_with_a_typed_error` |

Not covered by tests, and therefore claims you should treat as unverified: the
Tauri binary was never compiled on this machine (see the README), so the command
layer, the poller, the Drive integration and the tray behaviour have no executed
evidence behind them. `secrets_inject` is tested at the crypto layer — the sealed
box matches libsodium's `crypto_box_seal` byte layout — but not against the live
GitHub API.
