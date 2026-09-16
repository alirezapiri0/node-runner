//! Vault verification suite.
//!
//! These are not smoke tests. Each one pins a specific security property that
//! the design claims, so that a future refactor that quietly weakens the vault
//! fails CI rather than shipping.
//!
//! Properties covered:
//!
//! | Property | Test |
//! |---|---|
//! | Round trip fidelity | `round_trip_payload`, `round_trip_preserves_exact_bytes` |
//! | Wrong passphrase is a typed auth error, not undefined behaviour | `wrong_passphrase_is_typed_auth_error` |
//! | Every region is covered by integrity checking | `tamper_*` |
//! | Structural rejects happen before KDF work | `structural_rejects_are_fast` |
//! | Nonces and DEKs never repeat | `nonces_and_deks_are_unique_across_seals` |
//! | No plaintext or passphrase ever reaches disk | `no_plaintext_reaches_disk` |
//! | KDF parameters are recorded and upgradable | `kdf_parameters_are_recorded_and_agile` |
//! | MAC key is not the encryption key | `mac_key_is_independent_of_wrap_key` |
//! | Hostile input never panics | `arbitrary_bytes_never_panic`, `every_truncation_is_safe` |
//! | Parameter downgrades and allocation bombs are refused | `kdf_bounds_reject_downgrade_and_bomb` |
//! | Rotation actually rotates | `rotate_passphrase_invalidates_the_old_one`, `rekey_changes_dek` |
//! | Backup generation is usable after a damaged primary | `backup_generation_is_recoverable` |

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use nrvault::aead::AeadId;
use nrvault::kdf::{self, KdfParams};
use nrvault::lockmem::LockedBuf;
use nrvault::secret::MIN_PASSPHRASE_LEN;
use nrvault::vault::{
    EncryptedVault, UnlockRequest, WrapPolicy, FIXED_HEADER_LEN, MAC_LEN, MIN_FILE_LEN,
    WRAPPED_DEK_LEN,
};
use nrvault::{Passphrase, VaultError, VaultPayload, VaultStore};

const SENTINEL_NAME: &str = "GITHUB_PAT";
const SENTINEL_VALUE: &str = "ghp_SENTINEL_a1b2c3d4e5f6_MUST_NOT_APPEAR_ON_DISK";
const PASSPHRASE: &str = "correct-horse-battery-staple";

fn policy() -> WrapPolicy {
    WrapPolicy::test_fast()
}

fn payload_with_sentinel(now: u64) -> VaultPayload {
    let mut p = VaultPayload::new(now);
    p.set(SENTINEL_NAME, SENTINEL_VALUE, now);
    p.set("CF_TUNNEL_TOKEN", "cf-sentinel-token-value", now);
    p
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

#[test]
fn round_trip_payload() {
    let pass = Passphrase::new(PASSPHRASE);
    let now = 1_700_000_000u64;
    let mut original = payload_with_sentinel(now);
    original.set("GOOGLE_SA_JSON", r#"{"type":"service_account"}"#, now);

    let vault = EncryptedVault::seal_secrets(&original, &pass, &policy()).unwrap();
    let restored = vault
        .unseal_secrets(&UnlockRequest::passphrase(&pass))
        .unwrap();

    assert_eq!(restored.get(SENTINEL_NAME).unwrap(), SENTINEL_VALUE);
    assert_eq!(
        restored.get("GOOGLE_SA_JSON").unwrap(),
        r#"{"type":"service_account"}"#
    );
    assert_eq!(restored.names(), original.names());
}

#[test]
fn round_trip_preserves_exact_bytes() {
    let pass = Passphrase::new(PASSPHRASE);
    // Include bytes that are awkward for JSON and for length math.
    let raw: Vec<u8> = (0u8..=255).chain(0u8..=255).collect();
    let vault = EncryptedVault::seal_raw(&raw, &pass, &policy()).unwrap();
    let out = vault.unseal_raw(&UnlockRequest::passphrase(&pass)).unwrap();
    assert_eq!(out.plaintext.as_slice(), raw.as_slice());
    assert!(!out.used_os_path);
}

#[test]
fn empty_payload_round_trips() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_raw(b"", &pass, &policy()).unwrap();
    let out = vault.unseal_raw(&UnlockRequest::passphrase(&pass)).unwrap();
    assert!(out.plaintext.is_empty());
}

#[test]
fn serialization_is_canonical_and_stable() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_secrets(&payload_with_sentinel(42), &pass, &policy()).unwrap();

    let bytes = vault.to_bytes();
    let reparsed = EncryptedVault::from_bytes(&bytes).unwrap();
    // Byte-for-byte identical: the parser accepts exactly what the writer emits.
    assert_eq!(reparsed.to_bytes(), bytes);
    assert_eq!(reparsed.header, vault.header);
    assert_eq!(reparsed.mac, vault.mac);
    // Re-parsing an already-parsed vault is idempotent.
    assert_eq!(
        EncryptedVault::from_bytes(&reparsed.to_bytes())
            .unwrap()
            .mac,
        vault.mac
    );
}

#[test]
fn file_layout_matches_the_documented_length() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_raw(b"hello", &pass, &policy()).unwrap();
    let expected =
        FIXED_HEADER_LEN + vault.dpapi_blob.len() + WRAPPED_DEK_LEN + b"hello".len() + 16 + MAC_LEN;
    assert_eq!(vault.to_bytes().len(), expected);
    assert_eq!(vault.payload_plaintext_len().unwrap(), b"hello".len());
    assert!(expected >= MIN_FILE_LEN);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[test]
fn wrong_passphrase_is_typed_auth_error() {
    let pass = Passphrase::new(PASSPHRASE);
    let wrong = Passphrase::new("not-the-right-passphrase");
    let vault = EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy()).unwrap();

    let err = vault
        .unseal_secrets(&UnlockRequest::passphrase(&wrong))
        .expect_err("wrong passphrase must not open the vault");
    assert!(matches!(err, VaultError::Auth), "got {err:?}");

    // And it must not leak anything in its Display form.
    let rendered = format!("{err}");
    assert!(!rendered.contains(PASSPHRASE));
    assert!(!rendered.contains(SENTINEL_VALUE));
}

#[test]
fn a_wrong_passphrase_and_a_modified_payload_are_distinguishable() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_raw(b"data", &pass, &policy()).unwrap();

    // A wrong passphrase fails the DEK unwrap, which is an authenticated AEAD
    // operation, and is reported as an authentication failure.
    let wrong = Passphrase::new("definitely-not-it");
    let err = vault
        .unseal_raw(&UnlockRequest::passphrase(&wrong))
        .unwrap_err();
    assert!(matches!(err, VaultError::Auth), "got {err:?}");
    assert!(err.is_authentication_failure());
    assert!(!err.is_definite_tamper());

    // A modified payload, opened with the *correct* passphrase, fails the MAC --
    // and because the MAC key is reachable from the DEK, the failure is correctly
    // attributed to the file rather than to the credential. This is the property
    // that the passphrase-derived MAC key could not provide.
    let mut bytes = vault.to_bytes();
    let payload_start = FIXED_HEADER_LEN + vault.dpapi_blob.len() + WRAPPED_DEK_LEN;
    bytes[payload_start] ^= 0x01;
    let tampered = EncryptedVault::from_bytes(&bytes).unwrap();
    let err = tampered
        .unseal_raw(&UnlockRequest::passphrase(&pass))
        .unwrap_err();
    assert!(matches!(err, VaultError::Integrity), "got {err:?}");
    assert!(err.is_definite_tamper());
    assert!(!err.is_authentication_failure());

    // Independent of the error type: the file demonstrably changed, which needs
    // no key to establish.
    assert_ne!(
        tampered.envelope_fingerprint(),
        vault.envelope_fingerprint()
    );
    assert_eq!(vault.envelope_fingerprint(), vault.envelope_fingerprint());
}

#[test]
fn mac_verification_reports_definite_tamper() {
    // `verify_mac` is the authenticated check, and it is the one place where a
    // failure genuinely means "proven modification" rather than "wrong key".
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_raw(b"data", &pass, &policy()).unwrap();
    let dek = vault.open_dek(&UnlockRequest::passphrase(&pass)).unwrap();
    let mac_key = kdf::mac_key_from_dek(dek.as_array32().unwrap(), &vault.header.salt).unwrap();

    // Untouched: verifies.
    vault.verify_mac(mac_key.as_array32().unwrap()).unwrap();

    // Modified: proven.
    let mut bytes = vault.to_bytes();
    let payload_start = FIXED_HEADER_LEN + vault.dpapi_blob.len() + WRAPPED_DEK_LEN;
    bytes[payload_start + 1] ^= 0x01;
    let tampered = EncryptedVault::from_bytes(&bytes).unwrap();
    let err = tampered
        .verify_mac(mac_key.as_array32().unwrap())
        .unwrap_err();
    assert!(matches!(err, VaultError::Integrity));
    assert!(err.is_definite_tamper());
    assert!(!err.is_authentication_failure());
}

#[test]
fn keys_are_separated_by_purpose() {
    let pass = Passphrase::new(PASSPHRASE);
    let salt = [7u8; 32];

    // The wrapping key comes from the passphrase; the MAC key comes from the DEK.
    // They are derived from different input keying material, so they cannot
    // collide by accident and neither is the raw Argon2id output.
    let wrap_key = kdf::derive_wrap_key(&pass, &salt, KdfParams::floor()).unwrap();
    let dek = [9u8; 32];
    let mac_key = kdf::mac_key_from_dek(&dek, &salt).unwrap();

    assert_ne!(
        wrap_key.as_slice(),
        mac_key.as_slice(),
        "the wrapping key and the MAC key must be different keys"
    );
    assert_eq!(wrap_key.len(), 32);
    assert_eq!(mac_key.len(), 32);

    // Deterministic for the same inputs...
    let again = kdf::derive_wrap_key(&pass, &salt, KdfParams::floor()).unwrap();
    assert_eq!(again.as_slice(), wrap_key.as_slice());
    let mac_again = kdf::mac_key_from_dek(&dek, &salt).unwrap();
    assert_eq!(mac_again.as_slice(), mac_key.as_slice());

    // ...and salt-separated, so two installations sealing the same passphrase do
    // not produce interchangeable key material.
    let other = kdf::derive_wrap_key(&pass, &[8u8; 32], KdfParams::floor()).unwrap();
    assert_ne!(other.as_slice(), wrap_key.as_slice());

    // A different DEK must give a different MAC key, otherwise the MAC would not
    // follow the key and rekeying would not invalidate old tags.
    let other_mac = kdf::mac_key_from_dek(&[10u8; 32], &salt).unwrap();
    assert_ne!(other_mac.as_slice(), mac_key.as_slice());
}

// ---------------------------------------------------------------------------
// Tamper detection: one test per region
// ---------------------------------------------------------------------------

/// Flip one bit in `bytes` and assert the vault refuses to open.
fn assert_tamper_rejected(bytes: &[u8], offset: usize) {
    let pass = Passphrase::new(PASSPHRASE);
    let mut damaged = bytes.to_vec();
    damaged[offset] ^= 0x01;

    match EncryptedVault::from_bytes(&damaged) {
        Err(_) => {} // rejected structurally, which is also acceptable
        Ok(v) => {
            let err = v
                .unseal_raw(&UnlockRequest::passphrase(&pass))
                .expect_err("tampering must not go undetected");
            assert!(
                matches!(
                    err,
                    VaultError::Integrity | VaultError::Auth | VaultError::Format(_)
                ),
                "unexpected error for tamper at offset {offset}: {err:?}"
            );
        }
    }
}

#[test]
fn tamper_any_region_is_detected() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_raw(b"the quick brown fox", &pass, &policy()).unwrap();
    let bytes = vault.to_bytes();
    let payload_start = FIXED_HEADER_LEN + vault.dpapi_blob.len() + WRAPPED_DEK_LEN;

    let offsets = [
        10,                    // kdf id
        11,                    // aead id
        12,                    // memory cost
        21,                    // salt
        53,                    // nonce_kek
        65,                    // nonce_dek
        89,                    // flags
        92,                    // dpapi_len
        96,                    // reserved
        payload_start,         // first payload byte
        payload_start + 5,     // mid payload
        bytes.len() - 1,       // last MAC byte
        bytes.len() - MAC_LEN, // first MAC byte
    ];

    for offset in offsets {
        assert_tamper_rejected(&bytes, offset);
    }
}

#[test]
fn swapping_the_whole_payload_between_vaults_is_detected() {
    // Two vaults sealed with the same passphrase. Splicing B's ciphertext into A
    // must fail, because the header (salt, nonces) is bound into the AAD.
    let pass = Passphrase::new(PASSPHRASE);
    let a = EncryptedVault::seal_raw(b"payload A", &pass, &policy()).unwrap();
    let b = EncryptedVault::seal_raw(b"payload B", &pass, &policy()).unwrap();

    let mut spliced = a.clone();
    spliced.payload_ct = b.payload_ct.clone();
    // Note: NOT recomputing the MAC, which is the attacker's problem. The wrap
    // and header are intact, so the DEK unwraps and the MAC is what catches it.
    let err = spliced
        .unseal_raw(&UnlockRequest::passphrase(&pass))
        .unwrap_err();
    assert!(matches!(err, VaultError::Integrity), "got {err:?}");
    // The attribution is also unambiguous: this file is not the one we sealed.
    assert_ne!(spliced.envelope_fingerprint(), a.envelope_fingerprint());

    // Even a "helpful" attacker who recomputes the MAC cannot succeed, because
    // the MAC key is derived from a DEK they do not have.
    let dek = a.open_dek(&UnlockRequest::passphrase(&pass)).unwrap();
    let mac_key = kdf::mac_key_from_dek(dek.as_array32().unwrap(), &a.header.salt).unwrap();
    let mut forged = spliced.clone();
    forged.mac = [0u8; MAC_LEN];
    assert!(forged.verify_mac(mac_key.as_array32().unwrap()).is_err());
}

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

#[test]
fn structural_rejects_are_fast() {
    // Structural validation must complete without running the KDF. We seal with
    // deliberately heavy parameters and confirm that *parsing* a malformed file
    // still returns in well under the cost of a single derivation.
    let pass = Passphrase::new(PASSPHRASE);
    let heavy = WrapPolicy {
        kdf: Some(KdfParams::preferred()),
        aead: AeadId::Aes256Gcm,
        os_wrap: false,
        calibration_target_ms: 250,
    };
    let vault = EncryptedVault::seal_raw(b"x", &pass, &heavy).unwrap();
    let derive_ms = kdf::time_derive(KdfParams::preferred()).unwrap();

    let mut bad_magic = vault.to_bytes();
    bad_magic[0] = b'X';

    let start = std::time::Instant::now();
    let err = EncryptedVault::from_bytes(&bad_magic).unwrap_err();
    let elapsed = start.elapsed();
    assert!(matches!(err, VaultError::Format(_)));

    let elapsed_ms = elapsed.as_millis();
    assert!(
        elapsed_ms < derive_ms.max(20),
        "structural rejection took {elapsed_ms}ms; a derivation takes {derive_ms}ms, \
         which means the KDF is running before validation"
    );
}

#[test]
fn structural_rejection_cases() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_raw(b"abc", &pass, &policy()).unwrap();
    let good = vault.to_bytes();

    // Too short to be a vault at all.
    assert!(matches!(
        EncryptedVault::from_bytes(&[]).unwrap_err(),
        VaultError::Format(_)
    ));
    assert!(matches!(
        EncryptedVault::from_bytes(&good[..MIN_FILE_LEN - 1]).unwrap_err(),
        VaultError::Format(_)
    ));

    // Bad magic.
    let mut b = good.clone();
    b[0] = b'Z';
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::Format(_)
    ));

    // Unsupported version.
    let mut b = good.clone();
    b[8] = 99;
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::Unsupported(_)
    ));

    // Unsupported KDF id.
    let mut b = good.clone();
    b[10] = 7;
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::Unsupported(_)
    ));

    // Unsupported AEAD id.
    let mut b = good.clone();
    b[11] = 9;
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::Unsupported(_)
    ));

    // Non-canonical: reserved bytes set.
    let mut b = good.clone();
    b[96] = 1;
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::Format(_)
    ));

    // Non-canonical: OS-wrap flag without a blob.
    let mut b = good.clone();
    b[89] |= 0x01;
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::Format(_)
    ));

    // Unknown flag bits are refused rather than ignored.
    let mut b = good.clone();
    b[90] = 0x80;
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::Unsupported(_)
    ));

    // A lying dpapi_len.
    let mut b = good.clone();
    b[89] |= 0x01;
    b[92..96].copy_from_slice(&3000u32.to_le_bytes());
    assert!(EncryptedVault::from_bytes(&b).is_err());

    // An absurd dpapi_len.
    let mut b = good.clone();
    b[89] |= 0x01;
    b[92..96].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::Format(_)
    ));
}

#[test]
fn kdf_bounds_reject_downgrade_and_bomb() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_raw(b"abc", &pass, &policy()).unwrap();

    // A downgrade attack: rewrite the header to cheap parameters. It cannot
    // actually succeed, because the MAC covers the header -- but the parse must
    // also refuse it outright.
    let mut b = vault.to_bytes();
    b[12..16].copy_from_slice(&1u32.to_le_bytes()); // 1 KiB memory cost
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::KdfParams(_)
    ));

    // An allocation bomb: 2 GiB.
    let mut b = vault.to_bytes();
    b[12..16].copy_from_slice(&(2u32 * 1024 * 1024).to_le_bytes());
    assert!(matches!(
        EncryptedVault::from_bytes(&b).unwrap_err(),
        VaultError::KdfParams(_)
    ));

    // Creating with parameters below the floor is refused too.
    let too_weak = WrapPolicy {
        kdf: Some(KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }),
        aead: AeadId::Aes256Gcm,
        os_wrap: false,
        calibration_target_ms: 1,
    };
    assert!(matches!(
        EncryptedVault::seal_raw(b"x", &pass, &too_weak).unwrap_err(),
        VaultError::KdfParams(_)
    ));
}

#[test]
fn arbitrary_bytes_never_panic() {
    let pass = Passphrase::new(PASSPHRASE);
    let valid = EncryptedVault::seal_raw(b"seed", &pass, &policy())
        .unwrap()
        .to_bytes();

    let mut state = 0x12345678u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    // Phase 1: the parse path, at volume. Parsing does no key derivation, so
    // this is cheap and it is where every length/offset assumption lives.
    let mut structurally_valid = Vec::new();
    for _ in 0..5000 {
        let len = (next() % 400) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
        // Half the time, start from a real vault so we exercise the interesting
        // parse paths instead of only the length check.
        if next() % 2 == 0 && buf.len() >= valid.len() {
            buf[..valid.len()].copy_from_slice(&valid);
            let idx = (next() as usize) % buf.len();
            buf[idx] ^= (next() & 0xff) as u8;
        }
        if let Ok(v) = EncryptedVault::from_bytes(&buf) {
            structurally_valid.push(v);
        }
    }
    assert!(
        !structurally_valid.is_empty(),
        "the generator produced no structurally valid inputs, so phase 2 tested nothing"
    );

    // Phase 2: unsealing, on a bounded sample. Each attempt costs a real
    // derivation, so this is a sample rather than a full sweep.
    for v in structurally_valid.iter().take(40) {
        // Structurally valid garbage must still fail to authenticate.
        let wrong = Passphrase::new("some-other-passphrase-entirely");
        assert!(v.unseal_raw(&UnlockRequest::passphrase(&wrong)).is_err());
    }
}

#[test]
fn every_truncation_is_safe() {
    let pass = Passphrase::new(PASSPHRASE);
    let full = EncryptedVault::seal_raw(b"truncate me", &pass, &policy())
        .unwrap()
        .to_bytes();

    for len in 0..full.len() {
        let slice = &full[..len];
        match EncryptedVault::from_bytes(slice) {
            Err(_) => {}
            Ok(v) => {
                // A truncated payload can still be structurally plausible, so
                // the guarantee is that it never opens -- not that it never parses.
                assert!(
                    v.unseal_raw(&UnlockRequest::passphrase(&pass)).is_err(),
                    "a {len}-byte truncation of a {}-byte vault opened successfully",
                    full.len()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Uniqueness
// ---------------------------------------------------------------------------

#[test]
fn nonces_and_deks_are_unique_across_seals() {
    let pass = Passphrase::new(PASSPHRASE);
    let payload = payload_with_sentinel(9);

    let mut salts = std::collections::HashSet::new();
    let mut kek_nonces = std::collections::HashSet::new();
    let mut dek_nonces = std::collections::HashSet::new();
    let mut wraps = std::collections::HashSet::new();
    let mut ciphertexts = std::collections::HashSet::new();

    const ROUNDS: usize = 24;
    for _ in 0..ROUNDS {
        let v = EncryptedVault::seal_secrets(&payload, &pass, &policy()).unwrap();
        assert!(salts.insert(v.header.salt));
        assert!(kek_nonces.insert(v.header.nonce_kek));
        assert!(dek_nonces.insert(v.header.nonce_dek));
        assert!(wraps.insert(v.wrapped_dek_pass.clone()));
        assert!(ciphertexts.insert(v.payload_ct.clone()));
    }
    assert_eq!(salts.len(), ROUNDS);
    assert_eq!(dek_nonces.len(), ROUNDS);
}

// ---------------------------------------------------------------------------
// KDF agility
// ---------------------------------------------------------------------------

#[test]
fn kdf_parameters_are_recorded_and_agile() {
    let pass = Passphrase::new(PASSPHRASE);
    let weak = WrapPolicy {
        kdf: Some(KdfParams::floor()),
        aead: AeadId::Aes256Gcm,
        os_wrap: false,
        calibration_target_ms: 1,
    };
    let strong = WrapPolicy {
        kdf: Some(KdfParams::preferred()),
        aead: AeadId::Aes256Gcm,
        os_wrap: false,
        calibration_target_ms: 1,
    };

    let mut vault = EncryptedVault::seal_raw(b"agile", &pass, &weak).unwrap();
    assert_eq!(vault.header.kdf, KdfParams::floor());
    assert!(vault.kdf_is_below(&KdfParams::preferred()));

    // Re-seal under stronger parameters: the same passphrase must still work,
    // because old parameters are read from the file rather than assumed.
    vault
        .rotate_passphrase(&UnlockRequest::passphrase(&pass), &pass, &strong)
        .unwrap();
    assert_eq!(vault.header.kdf, KdfParams::preferred());
    assert!(!vault.kdf_is_below(&KdfParams::preferred()));

    let out = vault.unseal_raw(&UnlockRequest::passphrase(&pass)).unwrap();
    assert_eq!(out.plaintext.as_slice(), b"agile");
}

#[test]
fn calibration_stays_within_bounds() {
    let params = kdf::calibrate(250).unwrap();
    params.validate_for_creation().unwrap();
    assert!(params.m_cost_kib >= kdf::MIN_GENERATED_M_COST_KIB);
    assert!(params.m_cost_kib <= kdf::MAX_GENERATED_M_COST_KIB);
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

#[test]
fn rotate_passphrase_invalidates_the_old_one() {
    let old = Passphrase::new(PASSPHRASE);
    let new = Passphrase::new("a-completely-different-passphrase");
    let mut vault =
        EncryptedVault::seal_secrets(&payload_with_sentinel(3), &old, &policy()).unwrap();
    let before = vault.to_bytes();

    vault
        .rotate_passphrase(&UnlockRequest::passphrase(&old), &new, &policy())
        .unwrap();

    assert_ne!(
        vault.to_bytes(),
        before,
        "rotation must change the envelope"
    );
    assert!(matches!(
        vault
            .unseal_secrets(&UnlockRequest::passphrase(&old))
            .unwrap_err(),
        VaultError::Auth
    ));
    let restored = vault
        .unseal_secrets(&UnlockRequest::passphrase(&new))
        .unwrap();
    assert_eq!(restored.get(SENTINEL_NAME).unwrap(), SENTINEL_VALUE);
}

#[test]
fn rekey_changes_dek() {
    let pass = Passphrase::new(PASSPHRASE);
    let mut vault = EncryptedVault::seal_raw(b"rekey me", &pass, &policy()).unwrap();

    let dek_before = vault.open_dek(&UnlockRequest::passphrase(&pass)).unwrap();

    vault
        .rekey(&UnlockRequest::passphrase(&pass), &pass, &policy())
        .unwrap();

    let dek_after = vault.open_dek(&UnlockRequest::passphrase(&pass)).unwrap();

    assert_ne!(
        dek_before.as_slice(),
        dek_after.as_slice(),
        "rekey must produce a new data encryption key"
    );
    assert_eq!(
        vault
            .unseal_raw(&UnlockRequest::passphrase(&pass))
            .unwrap()
            .plaintext
            .as_slice(),
        b"rekey me"
    );
}

#[test]
fn update_payload_writes_without_touching_key_material() {
    // The write path. Its whole reason for existing is that it needs only the
    // DEK, so a session unlocked through the OS path can still save edits.
    let pass = Passphrase::new(PASSPHRASE);
    let mut vault =
        EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy()).unwrap();

    let wrapped_before = vault.wrapped_dek_pass.clone();
    let salt_before = vault.header.salt;
    let kdf_before = vault.header.kdf;
    let nonce_before = vault.header.nonce_dek;
    let ciphertext_before = vault.payload_ct.clone();

    let mut edited = payload_with_sentinel(2);
    edited.set("NEW_CREDENTIAL", "a-fresh-value", 2);
    let json = edited.to_json().unwrap();
    vault
        .update_payload(json.as_bytes(), &UnlockRequest::passphrase(&pass))
        .unwrap();

    // Key material is untouched, which is what makes this cheap and what keeps
    // the DKAPI and passphrase wraps valid.
    assert_eq!(vault.wrapped_dek_pass, wrapped_before);
    assert_eq!(vault.header.salt, salt_before);
    assert_eq!(vault.header.kdf, kdf_before);

    // ...while the payload nonce and ciphertext are both new.
    assert_ne!(
        vault.header.nonce_dek, nonce_before,
        "the nonce must rotate"
    );
    assert_ne!(vault.payload_ct, ciphertext_before);

    // The edit is visible, the old content is intact, and the whole thing still
    // survives a serialization round trip.
    let restored = vault
        .unseal_secrets(&UnlockRequest::passphrase(&pass))
        .unwrap();
    assert_eq!(restored.get("NEW_CREDENTIAL").unwrap(), "a-fresh-value");
    assert_eq!(restored.get(SENTINEL_NAME).unwrap(), SENTINEL_VALUE);

    let reparsed = EncryptedVault::from_bytes(&vault.to_bytes()).unwrap();
    let restored = reparsed
        .unseal_secrets(&UnlockRequest::passphrase(&pass))
        .unwrap();
    assert_eq!(restored.get("NEW_CREDENTIAL").unwrap(), "a-fresh-value");

    // A wrong credential still cannot open it after the write.
    assert!(vault
        .unseal_secrets(&UnlockRequest::passphrase(&Passphrase::new(
            "wrong-passphrase-xyz"
        )))
        .is_err());
}

#[test]
fn repeated_writes_never_reuse_a_payload_nonce() {
    // Nonce reuse under a fixed key is the one failure mode that breaks GCM
    // completely, and it is exactly the mistake a naive "re-save" would make.
    let pass = Passphrase::new(PASSPHRASE);
    let mut vault = EncryptedVault::seal_raw(b"start", &pass, &policy()).unwrap();

    let mut seen = std::collections::HashSet::new();
    seen.insert(vault.header.nonce_dek);

    for round in 0..24u8 {
        vault
            .update_payload(&[round; 8], &UnlockRequest::passphrase(&pass))
            .unwrap();
        assert!(
            seen.insert(vault.header.nonce_dek),
            "the payload nonce was reused on write {round}"
        );
    }
    assert_eq!(seen.len(), 25);
}

#[test]
fn rotation_requires_the_passphrase_not_just_an_open_session() {
    // The OS convenience path must not be sufficient to change the passphrase,
    // otherwise a stolen unlocked session could be used to lock the owner out.
    let pass = Passphrase::new(PASSPHRASE);
    let mut vault = EncryptedVault::seal_raw(b"x", &pass, &policy()).unwrap();
    let new = Passphrase::new("another-long-enough-passphrase");

    let err = vault
        .rotate_passphrase(&UnlockRequest::os_convenience(), &new, &policy())
        .unwrap_err();
    assert!(matches!(err, VaultError::NoUnlockMethod(_)));
}

// ---------------------------------------------------------------------------
// On-disk hygiene
// ---------------------------------------------------------------------------

#[test]
fn no_plaintext_reaches_disk() {
    let dir = TempDir::new();
    let store = VaultStore::new(dir.path());
    let pass = Passphrase::new(PASSPHRASE);
    let payload = payload_with_sentinel(1234);

    let vault = EncryptedVault::seal_secrets(&payload, &pass, &policy()).unwrap();
    store.save(&vault, Some(12)).unwrap();

    // Every file in the vault directory, including temp files and metadata, is
    // searched for the secrets and for the passphrase itself.
    let needles: Vec<&[u8]> = vec![
        SENTINEL_VALUE.as_bytes(),
        b"cf-sentinel-token-value",
        PASSPHRASE.as_bytes(),
        SENTINEL_NAME.as_bytes(),
        b"CF_TUNNEL_TOKEN",
    ];

    let mut scanned = 0usize;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        scanned += 1;
        let contents = std::fs::read(&path).unwrap();
        for needle in &needles {
            assert!(
                !contains(&contents, needle),
                "{} contains plaintext {:?}",
                path.display(),
                String::from_utf8_lossy(needle)
            );
        }
    }
    assert!(
        scanned >= 2,
        "expected vault.bin and vault.meta.json, scanned {scanned}"
    );

    // The metadata file must not name the credentials either.
    let meta = std::fs::read_to_string(store.meta_path()).unwrap();
    assert!(!meta.contains(SENTINEL_NAME));
    assert!(!meta.contains("GITHUB_PAT"));
}

#[test]
fn secrets_are_only_readable_through_the_store() {
    let dir = TempDir::new();
    let store = VaultStore::new(dir.path());
    let pass = Passphrase::new(PASSPHRASE);
    let payload = payload_with_sentinel(1);
    store
        .save(
            &EncryptedVault::seal_secrets(&payload, &pass, &policy()).unwrap(),
            None,
        )
        .unwrap();

    assert!(store.exists());
    let restored = store
        .load_and_unseal(&UnlockRequest::passphrase(&pass))
        .unwrap();
    assert_eq!(restored.get(SENTINEL_NAME).unwrap(), SENTINEL_VALUE);

    // Metadata records the unlock without recording what was unlocked.
    let meta = store.meta().unwrap();
    assert!(meta.last_unlock_at_unix.is_some());
    assert_eq!(meta.tamper_strikes, 0);

    // A views() projection is what the UI sees: names and timestamps, no values.
    let views = restored.views();
    assert_eq!(views.len(), 2);
    assert!(views
        .iter()
        .all(|v| !format!("{v:?}").contains(SENTINEL_VALUE)));
}

#[test]
fn backup_generation_is_recoverable() {
    let dir = TempDir::new();
    let store = VaultStore::new(dir.path());
    let pass = Passphrase::new(PASSPHRASE);

    let first = EncryptedVault::seal_raw(b"generation one", &pass, &policy()).unwrap();
    store.save(&first, None).unwrap();
    let second = EncryptedVault::seal_raw(b"generation two", &pass, &policy()).unwrap();
    store.save(&second, None).unwrap();

    assert!(
        store.backup_path().exists(),
        "a previous generation must be kept"
    );

    // Simulate a destroyed primary.
    std::fs::remove_file(store.vault_path()).unwrap();
    assert!(store.recoverable_from_backup());
    assert!(!store.exists());

    let recovered = store.load_backup().unwrap();
    let out = recovered
        .unseal_raw(&UnlockRequest::passphrase(&pass))
        .unwrap();
    assert_eq!(out.plaintext.as_slice(), b"generation one");
}

#[test]
fn torn_write_leaves_the_previous_vault_intact() {
    let dir = TempDir::new();
    let store = VaultStore::new(dir.path());
    let pass = Passphrase::new(PASSPHRASE);

    let good = EncryptedVault::seal_raw(b"durable", &pass, &policy()).unwrap();
    store.save(&good, None).unwrap();

    // A crash between "write temp file" and "rename" leaves an orphaned temp
    // file behind. The store must still read the committed vault.
    let tmp = nrvault::atomic::tmp_path(&store.vault_path());
    std::fs::write(&tmp, b"half-written garbage").unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(
        loaded
            .unseal_raw(&UnlockRequest::passphrase(&pass))
            .unwrap()
            .plaintext
            .as_slice(),
        b"durable"
    );
}

#[test]
fn tamper_ledger_records_and_clears() {
    let dir = TempDir::new();
    let store = VaultStore::new(dir.path());
    let pass = Passphrase::new(PASSPHRASE);
    store
        .save(
            &EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy()).unwrap(),
            None,
        )
        .unwrap();

    assert_eq!(store.record_tamper("mac mismatch on load").unwrap(), 1);
    assert_eq!(store.record_tamper("second event").unwrap(), 2);

    let meta = store.meta().unwrap();
    assert_eq!(meta.tamper_strikes, 2);
    assert_eq!(meta.tamper_log.len(), 2);
    assert_eq!(meta.tamper_log[0].detail, "second event", "newest first");

    store.clear_tampers().unwrap();
    let meta = store.meta().unwrap();
    assert_eq!(meta.tamper_strikes, 0);
    assert!(meta.tamper_log.is_empty());
}

#[test]
fn corrupt_vault_records_a_tamper_strike() {
    let dir = TempDir::new();
    let store = VaultStore::new(dir.path());
    let pass = Passphrase::new(PASSPHRASE);
    store
        .save(
            &EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy()).unwrap(),
            None,
        )
        .unwrap();

    // Flip a byte inside the payload ciphertext, leaving the structure valid.
    // Targeting the payload specifically matters: the error variant is what tells
    // the user whether their credential was wrong or their file was edited, so
    // this asserts the region rather than merely "something broke".
    let mut bytes = std::fs::read(store.vault_path()).unwrap();
    let payload_start = FIXED_HEADER_LEN + WRAPPED_DEK_LEN;
    assert!(
        bytes.len() > payload_start + 32,
        "the test vault is implausibly small to have a payload"
    );
    bytes[payload_start + 4] ^= 0x01;
    std::fs::write(store.vault_path(), &bytes).unwrap();

    let err = store
        .load_and_unseal(&UnlockRequest::passphrase(&pass))
        .unwrap_err();
    assert!(err.is_definite_tamper(), "got {err:?}");

    let meta = store.meta().unwrap();
    assert_eq!(meta.tamper_strikes, 1);
    assert_eq!(meta.tamper_log.len(), 1);
    assert!(!meta.tamper_log[0].detail.is_empty());
}

#[test]
fn a_mistyped_passphrase_does_not_raise_a_tamper_alarm() {
    // The whole point of the envelope fingerprint: without it, every typo would
    // look identical to tampering, and the ledger would cry wolf until nobody
    // trusted it.
    let dir = TempDir::new();
    let store = VaultStore::new(dir.path());
    let pass = Passphrase::new(PASSPHRASE);
    store
        .save(
            &EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy()).unwrap(),
            None,
        )
        .unwrap();

    for attempt in 0..3 {
        let wrong = Passphrase::new(format!("wrong-passphrase-attempt-{attempt}"));
        assert!(store
            .load_and_unseal(&UnlockRequest::passphrase(&wrong))
            .unwrap_err()
            .is_authentication_failure());
    }

    // Three failures, zero tamper strikes: the file never changed.
    let meta = store.meta().unwrap();
    assert_eq!(
        meta.tamper_strikes, 0,
        "typos must not be reported as tampering"
    );
    assert!(meta.tamper_log.is_empty());

    // And the real passphrase still works afterwards.
    let payload = store
        .load_and_unseal(&UnlockRequest::passphrase(&pass))
        .unwrap();
    assert_eq!(payload.get(SENTINEL_NAME).unwrap(), SENTINEL_VALUE);
}

#[test]
fn the_fingerprint_survives_a_legitimate_reseal() {
    // A rotation rewrites the envelope, so the recorded fingerprint must be
    // updated with it -- otherwise the next unlock would be misreported.
    let dir = TempDir::new();
    let store = VaultStore::new(dir.path());
    let pass = Passphrase::new(PASSPHRASE);
    let mut vault =
        EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy()).unwrap();
    store.save(&vault, None).unwrap();

    vault
        .rotate_passphrase(&UnlockRequest::passphrase(&pass), &pass, &policy())
        .unwrap();
    store.save(&vault, None).unwrap();

    assert_eq!(
        store.envelope_changed_since_seal(&vault),
        Some(false),
        "a re-sealed vault must not look modified"
    );
    assert_eq!(store.meta().unwrap().tamper_strikes, 0);
}

#[test]
fn destroy_removes_every_artifact() {
    let dir = TempDir::new();
    let store = VaultStore::new(dir.path());
    let pass = Passphrase::new(PASSPHRASE);
    store
        .save(
            &EncryptedVault::seal_raw(b"x", &pass, &policy()).unwrap(),
            None,
        )
        .unwrap();
    store
        .save(
            &EncryptedVault::seal_raw(b"y", &pass, &policy()).unwrap(),
            None,
        )
        .unwrap();
    assert!(store.exists() && store.backup_path().exists() && store.meta_path().exists());

    store.destroy().unwrap();
    assert!(!store.exists());
    assert!(!store.backup_path().exists());
    assert!(!store.meta_path().exists());
    // Destroying is idempotent.
    store.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// Payload model
// ---------------------------------------------------------------------------

#[test]
fn payload_name_validation_blocks_shell_metacharacters() {
    // Names become environment variable names on the runner, so anything that
    // could smuggle a shell metacharacter must be rejected at this boundary.
    for bad in [
        "",
        "lowercase",
        "with space",
        "with-dash",
        "SEMI;COLON",
        "$(whoami)",
        "NEW\nLINE",
        "QUOTE\"'",
        &"A".repeat(65),
    ] {
        assert!(
            VaultPayload::validate_name(bad).is_err(),
            "{bad:?} should have been rejected"
        );
    }
    for good in ["GITHUB_PAT", "A", "CF_TUNNEL_TOKEN", "X_9"] {
        assert!(
            VaultPayload::validate_name(good).is_ok(),
            "{good:?} should be allowed"
        );
    }
}

#[test]
fn payload_set_get_remove_tracks_rotation() {
    let mut p = VaultPayload::new(100);
    p.set("GITHUB_PAT", "v1", 100);
    assert_eq!(p.get("GITHUB_PAT").unwrap(), "v1");
    assert_eq!(p.secrets["GITHUB_PAT"].created_at_unix, 100);
    assert_eq!(p.secrets["GITHUB_PAT"].rotated_at_unix, None);

    p.set("GITHUB_PAT", "v2", 200);
    assert_eq!(p.get("GITHUB_PAT").unwrap(), "v2");
    assert_eq!(
        p.secrets["GITHUB_PAT"].created_at_unix, 100,
        "created is sticky"
    );
    assert_eq!(p.secrets["GITHUB_PAT"].rotated_at_unix, Some(200));
    assert_eq!(p.updated_at_unix, 200);

    p.remove("GITHUB_PAT", 300).unwrap();
    assert!(matches!(
        p.get("GITHUB_PAT").unwrap_err(),
        VaultError::UnknownSecret(_)
    ));
    assert!(p.remove("GITHUB_PAT", 300).is_err());
}

#[test]
fn payload_debug_output_is_redacted() {
    let p = payload_with_sentinel(1);
    let rendered = format!("{p:?}");
    assert!(
        !rendered.contains(SENTINEL_VALUE),
        "payload Debug leaked a value: {rendered}"
    );
    assert!(!rendered.contains("cf-sentinel-token-value"));
    assert!(rendered.contains(SENTINEL_NAME), "names are fine to show");

    let entry = &p.secrets[SENTINEL_NAME];
    let rendered = format!("{entry:?}");
    assert!(!rendered.contains(SENTINEL_VALUE));
}

#[test]
fn passphrase_debug_and_display_are_redacted() {
    let pass = Passphrase::new(PASSPHRASE);
    let rendered = format!("{pass:?}");
    assert!(!rendered.contains(PASSPHRASE));
    assert!(rendered.contains("redacted"));

    // Errors must not carry it either.
    let err = Passphrase::new("short").check_policy().unwrap_err();
    assert!(!format!("{err}").contains("short"));
    assert!(!format!("{err:?}").contains("short"));
}

#[test]
fn passphrase_policy_is_enforced_at_creation_only() {
    assert!(Passphrase::new("short").check_policy().is_err());
    assert!(Passphrase::new("alllowercaseletters")
        .check_policy()
        .is_err());
    assert!(Passphrase::new("a".repeat(MIN_PASSPHRASE_LEN))
        .check_policy()
        .is_err());
    assert!(Passphrase::new("MixedCase123!").check_policy().is_ok());

    // A vault sealed with a passphrase that would not pass today's policy must
    // still open: locking users out of existing vaults is worse than a weak one.
    let legacy = Passphrase::new("weakpass");
    let vault = EncryptedVault::seal_raw(b"legacy", &legacy, &policy()).unwrap();
    assert_eq!(
        vault
            .unseal_raw(&UnlockRequest::passphrase(&legacy))
            .unwrap()
            .plaintext
            .as_slice(),
        b"legacy"
    );
}

#[test]
fn vault_debug_output_is_redacted() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy()).unwrap();
    let rendered = format!("{vault:?}");
    assert!(
        !rendered.contains(SENTINEL_VALUE),
        "vault Debug leaked a plaintext value"
    );
    // The Debug impl is a structural description, not a field dump.
    assert!(rendered.contains("EncryptedVault"));
    assert!(rendered.contains("Argon2id"));
    assert!(rendered.contains("mac"));
}

// ---------------------------------------------------------------------------
// Memory hygiene
// ---------------------------------------------------------------------------

#[test]
fn locked_buffers_zeroize_and_report_pinning() {
    let mut buf = LockedBuf::copy_from(b"super-secret-key-material");
    assert_eq!(buf.len(), 25);
    assert!(
        buf.as_array32().is_err(),
        "a 25-byte buffer must not silently become a key"
    );

    let key = LockedBuf::zeroed(32);
    assert!(key.as_array32().is_ok());
    assert_eq!(key.as_slice(), &[0u8; 32]);

    // On Windows the pages should be pinned; elsewhere the API reports false
    // rather than pretending.
    if cfg!(windows) {
        assert!(key.is_locked(), "VirtualLock should have succeeded");
    }

    let rendered = format!("{buf:?}");
    assert!(!rendered.contains("super-secret"));

    buf.unlock();
    assert!(!buf.is_locked());
}

#[test]
fn error_messages_never_contain_secret_material() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy()).unwrap();

    let err = vault
        .unseal_secrets(&UnlockRequest::passphrase(&Passphrase::new(
            "wrong-passphrase-here",
        )))
        .unwrap_err();
    let text = format!("{err} {err:?}");
    assert!(!text.contains(PASSPHRASE));
    assert!(!text.contains(SENTINEL_VALUE));
}

#[test]
fn structural_summary_is_informative_and_secret_free() {
    let pass = Passphrase::new(PASSPHRASE);
    let vault = EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy()).unwrap();
    let summary = vault.structural_summary();
    assert!(summary.contains("Argon2id"));
    assert!(summary.contains("AES-256-GCM"));
    assert!(summary.contains("v1"));
    assert!(!summary.contains(SENTINEL_VALUE));
}

// ---------------------------------------------------------------------------
// OS-protected path
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod dpapi {
    use super::*;

    #[test]
    fn os_protector_round_trip() {
        let probe = nrvault::keywrap::probe_protector();
        println!("protector status: {probe:?}");
        assert_ne!(
            probe,
            nrvault::ProtectorStatus::Unsupported,
            "DPAPI must be available on Windows"
        );
        assert_eq!(
            probe,
            nrvault::ProtectorStatus::Healthy,
            "the OS protector round trip failed; the vault would not reopen on this machine"
        );
    }

    #[test]
    fn convenience_unlock_without_a_passphrase() {
        let pass = Passphrase::new(PASSPHRASE);
        let policy = WrapPolicy {
            kdf: Some(KdfParams::floor()),
            aead: AeadId::Aes256Gcm,
            os_wrap: true,
            calibration_target_ms: 1,
        };
        let vault =
            EncryptedVault::seal_secrets(&payload_with_sentinel(1), &pass, &policy).unwrap();
        assert!(vault.has_os_wrap());
        assert_eq!(vault.binding(), Some(nrvault::TpmBinding::UserProfileScope));

        // No passphrase at all: the OS path opens it.
        let restored = vault
            .unseal_secrets(&UnlockRequest::os_convenience())
            .unwrap();
        assert_eq!(restored.get(SENTINEL_NAME).unwrap(), SENTINEL_VALUE);

        // And the passphrase path still works on the same vault.
        let restored = vault
            .unseal_secrets(&UnlockRequest::passphrase(&pass))
            .unwrap();
        assert_eq!(restored.get(SENTINEL_NAME).unwrap(), SENTINEL_VALUE);

        // The declared binding is reported honestly as profile-scope.
        assert!(nrvault::TpmBinding::UserProfileScope
            .label()
            .contains("not TPM-bound"));
    }

    #[test]
    fn os_blob_is_bound_to_its_entropy() {
        // A blob wrapped for one salt must not unwrap for another, which is what
        // stops a blob lifted from one vault being pasted into another.
        let dek = LockedBuf::copy_from(b"0123456789abcdef0123456789abcdef");
        let blob = nrvault::keywrap::os_wrap(dek.as_slice(), &[1u8; 32]).unwrap();

        let round = nrvault::keywrap::os_unwrap(&blob, &[1u8; 32]).unwrap();
        assert_eq!(round.as_slice(), dek.as_slice());

        assert!(
            nrvault::keywrap::os_unwrap(&blob, &[2u8; 32]).is_err(),
            "a blob must not unwrap under a different per-installation salt"
        );
    }

    #[test]
    fn tampering_with_the_os_blob_is_detected() {
        let pass = Passphrase::new(PASSPHRASE);
        let policy = WrapPolicy {
            kdf: Some(KdfParams::floor()),
            aead: AeadId::Aes256Gcm,
            os_wrap: true,
            calibration_target_ms: 1,
        };
        let vault = EncryptedVault::seal_raw(b"protected", &pass, &policy).unwrap();
        let mut bytes = vault.to_bytes();
        let mid = FIXED_HEADER_LEN + vault.dpapi_blob.len() / 2;
        bytes[mid] ^= 0x01;

        let damaged = EncryptedVault::from_bytes(&bytes).unwrap();
        // The OS path cannot use the damaged blob: DPAPI itself refuses it.
        assert!(damaged
            .unseal_raw(&UnlockRequest::os_convenience())
            .is_err());
        // The passphrase path still unwraps the DEK (the wrap covers the header,
        // not the blob), and then the MAC catches the edit and attributes it
        // correctly to the file rather than to the credential.
        let err = damaged
            .unseal_raw(&UnlockRequest::passphrase(&pass))
            .unwrap_err();
        assert!(err.is_definite_tamper(), "got {err:?}");
        assert_ne!(damaged.envelope_fingerprint(), vault.envelope_fingerprint());
    }
}

// ---------------------------------------------------------------------------
// Sealed boxes (GitHub Actions secret injection)
// ---------------------------------------------------------------------------

mod sealed_boxes {
    use nrvault::sealbox::{self, RepositoryKey, SEALED_OVERHEAD};

    /// Base64-encode a 32-byte key the way GitHub's API returns it.
    fn b64_key(pk: [u8; 32]) -> String {
        use base64ct::{Base64, Encoding};
        Base64::encode_string(&pk)
    }

    #[test]
    fn overhead_is_exactly_the_libsodium_sealbytes() {
        // 32-byte ephemeral public key + 16-byte Poly1305 tag. This is the
        // strongest offline evidence available that the construction is the
        // libsodium one: any other construction would not land on 48.
        assert_eq!(SEALED_OVERHEAD, 48);
        assert_eq!(nrvault::sealbox::SEALED_OVERHEAD, 48);

        let (_sk, pk) = sealbox::generate_keypair();
        let key = RepositoryKey::from_base64("kid-1", &b64_key(pk.to_bytes())).unwrap();

        for len in [0usize, 1, 32, 1024, 65_536] {
            let plaintext = vec![0x41u8; len];
            let sealed = key.seal(&plaintext).unwrap();
            let raw = sealbox::decode_sealed(&sealed).unwrap();
            assert_eq!(raw.len(), len + SEALED_OVERHEAD);
        }
    }

    #[test]
    fn round_trip_recovers_the_secret() {
        let (sk, pk) = sealbox::generate_keypair();
        let key = RepositoryKey::from_base64("kid-2", &b64_key(pk.to_bytes())).unwrap();

        let secret = br#"{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----"}"#;
        let sealed = key.seal(secret).unwrap();
        let raw = sealbox::decode_sealed(&sealed).unwrap();
        let opened = sealbox::unseal(&sk, &raw).unwrap();
        assert_eq!(opened.as_slice(), secret);
    }

    #[test]
    fn sealing_is_nondeterministic() {
        let (_sk, pk) = sealbox::generate_keypair();
        let key = RepositoryKey::from_base64("kid-3", &b64_key(pk.to_bytes())).unwrap();

        let a = key.seal(b"same plaintext").unwrap();
        let b = key.seal(b"same plaintext").unwrap();
        assert_ne!(
            a.as_str(),
            b.as_str(),
            "an ephemeral key is generated per seal, so ciphertexts must differ"
        );
    }

    #[test]
    fn only_the_intended_recipient_can_open() {
        let (sk, pk) = sealbox::generate_keypair();
        let (other_sk, _other_pk) = sealbox::generate_keypair();
        let key = RepositoryKey::from_base64("kid-4", &b64_key(pk.to_bytes())).unwrap();

        let raw = sealbox::decode_sealed(&key.seal(b"bound to one repository").unwrap()).unwrap();
        assert!(sealbox::unseal(&sk, &raw).is_ok());
        assert!(
            sealbox::unseal(&other_sk, &raw).is_err(),
            "a sealed box must be bound to exactly one recipient"
        );
    }

    #[test]
    fn tampering_with_a_sealed_box_is_rejected() {
        let (sk, pk) = sealbox::generate_keypair();
        let key = RepositoryKey::from_base64("kid-5", &b64_key(pk.to_bytes())).unwrap();
        let raw = sealbox::decode_sealed(&key.seal(b"credential material").unwrap()).unwrap();

        for offset in [0usize, 31, 32, raw.len() - 1] {
            let mut damaged = raw.to_vec();
            damaged[offset] ^= 0x01;
            assert!(
                sealbox::unseal(&sk, &damaged).is_err(),
                "tampering at offset {offset} was accepted"
            );
        }
    }

    #[test]
    fn malformed_keys_are_rejected_with_a_typed_error() {
        assert!(RepositoryKey::from_base64("kid", "not base64!!").is_err());
        // Valid base64 but the wrong length.
        assert!(RepositoryKey::from_base64("kid", "AAAA").is_err());

        // Whitespace from a formatted API response is tolerated.
        let (_sk, pk) = sealbox::generate_keypair();
        let padded = format!("  {}\n", b64_key(pk.to_bytes()));
        let key = RepositoryKey::from_base64("kid", &padded).unwrap();
        assert_eq!(key.public_key_bytes(), pk.to_bytes());
    }

    #[test]
    fn debug_output_does_not_leak_key_material() {
        let (_sk, pk) = sealbox::generate_keypair();
        let key = RepositoryKey::from_base64("kid-6", &b64_key(pk.to_bytes())).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("kid-6"));
        // The base64 form of the key must not be printed.
        assert!(!rendered.contains(&b64_key(pk.to_bytes())));
        assert!(rendered.contains("32 bytes"));
    }
}

// ---------------------------------------------------------------------------

/// A self-deleting temporary directory.
///
/// Hand-rolled rather than depending on `tempfile`: that crate pulls
/// `getrandom 0.4` / `windows-link`, which needs `raw-dylib` import-library
/// generation and therefore an assembler in the build environment. The tests
/// need exactly two things from a temp dir -- a unique path and cleanup -- and
/// this is both.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "nrvault-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Substring search over raw bytes.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
