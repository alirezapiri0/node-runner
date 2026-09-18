#!/usr/bin/env bash
#
# Watchdog.
#
# The handover is the only mechanism that starts the next node, which makes it a
# single point of failure: if a node is killed outright — the runner is
# reclaimed, the 6-hour ceiling is hit early, the backup hangs past the job
# timeout — nothing dispatches a successor and the loop simply stops. The
# operator would find out whenever they next looked at the app.
#
# This runs on GitHub's own scheduler, which is independent of the node it is
# watching, and starts a node only when the heartbeat has genuinely gone quiet.
#
# The staleness threshold is deliberately generous. Heartbeats are published
# roughly every 60s, but the snapshot upload writes one only at its boundaries,
# so a large upload can legitimately leave a gap of several minutes. Restarting a
# node that is merely busy is worse than a slow recovery: two live nodes mean two
# workloads feeding one state tree, and while the lease prevents a torn snapshot,
# it does not prevent two workloads from disagreeing about the data. Hence 40
# minutes — long enough to cover a slow backup, short enough still to be a small
# fraction of the 340-minute cycle.

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

readonly STALE_AFTER_SECONDS="${STALE_AFTER_SECONDS:-2400}"

main() {
  require_cmd rclone curl jq
  rclone_configure

  if killswitch_engaged; then
    log "kill switch is engaged; the watchdog will not start a node"
    return 0
  fi

  local raw=""
  if ! raw=$(rclone cat "${DRIVE_REMOTE}:${HEARTBEAT_FILE}" 2>/dev/null); then
    log "no heartbeat found; dispatching the first node"
    dispatch_node "bootstrap" "no heartbeat exists yet" "blue"
    return 0
  fi

  local heartbeat_unix phase slot age
  heartbeat_unix=$(printf '%s' "$raw" | jq -r '.heartbeat_unix // 0')
  phase=$(printf '%s' "$raw" | jq -r '.phase // "unknown"')
  slot=$(printf '%s' "$raw" | jq -r '.slot // "unknown"')
  age=$(( $(now_unix) - heartbeat_unix ))

  if (( age <= STALE_AFTER_SECONDS )); then
    log "node ${slot} is healthy (phase=${phase}, last heartbeat ${age}s ago)"
    return 0
  fi

  warn "node ${slot} has been silent for ${age}s (phase=${phase}); treating it as dead"
  dispatch_node "failover" "watchdog: no heartbeat for ${age}s" "$slot"
}

# Take the opposite slot from the node that died, so the ledger and the UI make
# it obvious that this is a recovery rather than a normal rotation.
dispatch_node() {
  local reason="$1" detail="$2" dead_slot="${3:-blue}"
  local next_slot
  case "$dead_slot" in
    blue) next_slot=green ;;
    *) next_slot=blue ;;
  esac

  local target_ref="${TARGET_REF:-main}"
  [[ -z "$target_ref" ]] && target_ref="main"

  log "dispatching a node (slot ${next_slot}, reason ${reason}): ${detail}"

  local body
  body=$(jq -n \
    --arg slot "$next_slot" \
    --arg reason "$reason" \
    --arg ref "$target_ref" \
    '{ref:$ref, inputs:{slot:$slot, reason:$reason, commit:""}}')

  if gh_api POST "/repos/${GITHUB_REPOSITORY}/actions/workflows/${WORKFLOW_FILE}/dispatches" "$body" \
      >/dev/null 2>"${PIPE_DIR}/watchdog-dispatch.err"; then
    log "node dispatched"
  else
    # Exiting non-zero here is deliberate: this is the last line of defence, and
    # a silent watchdog failure is the one outcome the operator cannot recover
    # from without noticing. A failed run sends a notification.
    die "could not dispatch a node: $(tr -d '\r' <"${PIPE_DIR}/watchdog-dispatch.err" | tail -n 3)"
  fi
}

main "$@"
