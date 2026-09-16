#!/usr/bin/env bash
# shellcheck shell=bash
#
# Restore the newest committed snapshot into WORK_DIR.
#
# Selection is driven by the commit records rather than by directory listing
# order. A directory can exist and be incomplete: `rclone copy` creates the
# destination first and fills it in, so the lexicographically newest snapshot
# directory may be a half-finished upload. The commit record is written *after*
# the upload is verified, so its existence is the only durable signal that a
# snapshot is complete.

readonly COMMIT_ROOT="${STATE_ROOT}/COMMIT"

# Print the newest commit record's snapshot path, or nothing when there is none.
latest_committed_snapshot() {
  local records
  records=$(retry 3 rclone lsf --files-only "${DRIVE_REMOTE}:${COMMIT_ROOT}/" 2>/dev/null \
    | LC_ALL=C sort || true)
  [[ -n "$records" ]] || return 0

  local newest
  newest=$(printf '%s\n' "$records" | tail -n 1)
  local raw
  raw=$(retry 3 rclone cat "${DRIVE_REMOTE}:${COMMIT_ROOT}/${newest}" 2>/dev/null) || return 0

  # A torn commit record is treated as absent, not as an error: the previous
  # snapshot is still perfectly good, and a crashed predecessor should not be
  # able to strand the successor on an unreadable file.
  printf '%s' "$raw" | jq -r '.snapshot // empty' 2>/dev/null || true
}

restore_from_drive() {
  mkdir -p "$WORK_DIR"

  local snapshot
  snapshot=$(latest_committed_snapshot)

  if [[ -z "$snapshot" ]]; then
    warn "no committed snapshot found; starting from an empty work directory"
    log "this is expected on the very first cycle"
    return 0
  fi

  log "restoring ${snapshot} -> ${WORK_DIR}"

  # No `--delete-*` flags, and not `rclone sync`: restore must be additive. A
  # sync here would let a snapshot that lost files (a partially restored
  # snapshot, or a hand-edited one) silently delete the local tree, and the
  # local tree is the only thing that has not been through the network yet.
  retry 3 rclone copy "${DRIVE_REMOTE}:${snapshot}" "$WORK_DIR" \
    --transfers 8 --checkers 16 --fast-list \
    --exclude '/MANIFEST.sha256' \
    || die "restore failed for ${snapshot}"

  local manifest="${PIPE_DIR}/MANIFEST.sha256"
  if rclone copyto "${DRIVE_REMOTE}:${snapshot}/MANIFEST.sha256" "$manifest" >/dev/null 2>&1; then
    # Verify before the workload is allowed to touch the tree. Restoring a
    # corrupted snapshot and then running the workload on it converts a
    # recoverable backup problem into an unrecoverable data problem.
    manifest_verify "$WORK_DIR" "$manifest" || die "restored snapshot failed verification"
    log "restored snapshot verified against its manifest"
  else
    warn "snapshot has no manifest; skipping verification"
  fi
}
