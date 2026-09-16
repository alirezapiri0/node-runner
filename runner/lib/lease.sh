#!/usr/bin/env bash
# shellcheck shell=bash
#
# Single-writer lease.
#
# The successor node is dispatched *before* the predecessor exits, which is the
# only way to keep the endpoint continuously served without a gap. That overlap
# is deliberate, and it means for a couple of minutes there are genuinely two
# live nodes. The lease is what stops the second one from restoring and writing
# while the first is still snapshotting: without it, the successor would start
# mutating a tree the predecessor is midway through hashing.

readonly LEASE_PATH="${STATE_ROOT}/lease.json"
readonly LEASE_STALE_SECONDS="${LEASE_STALE_SECONDS:-900}"

# Acquire the lease for this run, waiting for a predecessor to release it.
#
# Returns 0 when this run owns the lease. Never force-breaks a lease that looks
# fresh: a live predecessor mid-snapshot is exactly the case the lease exists to
# protect, and stealing it would produce the torn backup the whole design is
# built to avoid.
lease_acquire() {
  local deadline=$(( $(now_unix) + ${LEASE_WAIT_SECONDS:-420} ))
  local run_key="${GITHUB_RUN_ID:-local}-${SLOT:-?}"
  local waiting_logged=0

  while :; do
    local raw=""
    raw=$(retry 2 rclone cat "${DRIVE_REMOTE}:${LEASE_PATH}" 2>/dev/null || true)

    if [[ -n "$raw" ]]; then
      local holder age
      holder=$(printf '%s' "$raw" | jq -r '.run_key // "unknown"' 2>/dev/null || echo unknown)
      age=$(( $(now_unix) - $(printf '%s' "$raw" | jq -r '.heartbeat_unix // 0' 2>/dev/null || echo 0) ))

      if [[ "$holder" == "$run_key" ]]; then
        return 0
      fi
      if (( age > LEASE_STALE_SECONDS )); then
        warn "breaking a stale lease held by ${holder} (${age}s since its last heartbeat)"
      else
        if (( waiting_logged == 0 )); then
          log "waiting for the lease held by ${holder} (last heartbeat ${age}s ago)"
          waiting_logged=1
        fi
        if (( $(now_unix) >= deadline )); then
          die "timed out waiting for the lease held by ${holder}"
        fi
        sleep 10
        continue
      fi
    fi

    lease_write "$run_key" && {
      log "lease acquired (${run_key})"
      return 0
    }
    sleep 5
  done
}

lease_write() {
  local run_key="$1"
  local payload
  payload=$(jq -n \
    --arg run_key "$run_key" \
    --arg slot "${SLOT:-?}" \
    --argjson run_id "${GITHUB_RUN_ID:-0}" \
    --argjson heartbeat_unix "$(now_unix)" \
    '{run_key:$run_key, slot:$slot, run_id:$run_id, heartbeat_unix:$heartbeat_unix}')

  printf '%s' "$payload" >"${PIPE_DIR}/lease.json"
  retry 3 rclone copyto "${PIPE_DIR}/lease.json" "${DRIVE_REMOTE}:${LEASE_PATH}" >/dev/null 2>&1
}

# Refresh the lease timestamp so the successor does not consider it abandoned
# while a long upload is in flight.
lease_renew() { lease_write "${GITHUB_RUN_ID:-local}-${SLOT:-?}"; }

# Release the lease. Best-effort: a failed release costs the successor one
# staleness timeout, and `rclone delete` of a file that is already gone is not
# worth failing a cycle over.
lease_release() {
  if retry 2 rclone deletefile "${DRIVE_REMOTE}:${LEASE_PATH}" >/dev/null 2>&1; then
    log "lease released"
  else
    warn "could not release the lease (the successor will break it after ${LEASE_STALE_SECONDS}s)"
  fi
}
