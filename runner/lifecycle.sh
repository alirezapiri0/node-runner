#!/usr/bin/env bash
#
# Node lifecycle orchestrator.
#
# Runs one compute node from bootstrap to handover. The wall-clock shape of a
# cycle, in minutes from script start:
#
#     0      preflight: tools, credentials, Drive reachability
#     1      acquire the single-writer lease
#     2-6    restore the newest committed snapshot and verify it
#     6      acknowledge the commit (only now is the predecessor free to stop)
#     6-8    bind the static domain, start the workload
#     8-325  runtime gate: publish heartbeats, honour the kill switch
#   325      freeze, flush, snapshot, verify, commit, prune
#   325-331  dispatch the successor and wait for its acknowledgement
#   <=335    drain and exit
#
# Every number above is a bound, not a hope: the job ceiling is 360 minutes, and
# the design keeps roughly 25 minutes of slack for runner-startup skew and for a
# slow snapshot. The reason the successor is dispatched *before* this node exits
# is that the ceiling applies per job, so the successor has to burn some of its
# own budget while this node is still winding down in order to avoid a gap.

set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/manifest.sh
source "${SCRIPT_DIR}/lib/manifest.sh"
# shellcheck source=lib/lease.sh
source "${SCRIPT_DIR}/lib/lease.sh"
# shellcheck source=lib/restore.sh
source "${SCRIPT_DIR}/lib/restore.sh"
# shellcheck source=lib/freeze.sh
source "${SCRIPT_DIR}/lib/freeze.sh"
# shellcheck source=lib/backup.sh
source "${SCRIPT_DIR}/lib/backup.sh"
# shellcheck source=lib/handover.sh
source "${SCRIPT_DIR}/lib/handover.sh"
# shellcheck source=lib/drain.sh
source "${SCRIPT_DIR}/lib/drain.sh"

mkdir -p "$PIPE_DIR"
touch "$LOG_FILE"

# Assigned before being made readonly: `readonly X="$(cmd)"` masks the command's
# own exit status, which would hide a failure of `now_unix`.
START_UNIX=$(now_unix)
readonly START_UNIX
LAST_GOOD_COMMIT="${PREDECESSOR_COMMIT:-}"
HANDOVER_DONE=0
TUNNEL_PID=""
WORKLOAD_PID=""

usage() {
  cat <<'EOF'
usage: lifecycle.sh [--slot blue|green] [--commit <utc-ts>] [--reason <reason>]

  --slot    logical node identity (ping-pongs across handovers)
  --commit  the commit the predecessor published (recorded as our parent)
  --reason  why this node started: cycle | manual | failover | killswitch
EOF
}

parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      --slot)   SLOT="${2:-}"; shift 2 ;;
      --commit) PREDECESSOR_COMMIT="${2:-}"; shift 2 ;;
      --reason) NODE_REASON="${2:-cycle}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "unknown argument: $1" ;;
    esac
  done
  SLOT="${SLOT:-manual}"
  NODE_REASON="${NODE_REASON:-manual}"
  LAST_GOOD_COMMIT="${PREDECESSOR_COMMIT:-}"
}

# --- failure handling ------------------------------------------------------

# A failure anywhere after the snapshot would otherwise leave the loop dead: the
# state is safe on Drive, but nothing would start the next node. So the failure
# path runs the same handover as the happy path, using the last commit that is
# known to be good, and marks the successor as `emergency` so the operator sees
# a degraded cycle rather than a silent one.
emergency_handover() {
  local exit_code=$?
  (( exit_code == 0 )) && return 0
  (( HANDOVER_DONE == 1 )) && return 0
  HANDOVER_DONE=1

  set +e
  trap - ERR EXIT

  warn "lifecycle failed (exit ${exit_code}); attempting an emergency handover"

  thaw_workload >/dev/null 2>&1 || true
  heartbeat_write "failed" 0 0 "$LAST_GOOD_COMMIT" >/dev/null 2>&1 || true

  if [[ -z "$LAST_GOOD_COMMIT" ]]; then
    # Nothing has ever been committed, so there is no state for a successor to
    # restore and starting one would just repeat this failure on a fresh billing
    # hour. Fail visibly instead.
    warn "no known-good commit to hand over; leaving the node stopped"
    warn "check the ledger and the run log before starting a new node"
    drain_node "" "emergency-no-state" >/dev/null 2>&1 || true
    return "$exit_code"
  fi

  if ! killswitch_engaged; then
    if dispatch_successor "$LAST_GOOD_COMMIT" >/dev/null 2>&1; then
      log "successor dispatched for the last known-good commit ${LAST_GOOD_COMMIT}"
      wait_for_ack "$LAST_GOOD_COMMIT" >/dev/null 2>&1 \
        || warn "successor did not acknowledge within ${ACK_TIMEOUT_SECONDS}s"
    else
      warn "could not dispatch a successor; the node will stop"
    fi
  else
    log "kill switch engaged; not dispatching a successor"
  fi

  drain_node "$LAST_GOOD_COMMIT" "emergency" >/dev/null 2>&1 || true
  return "$exit_code"
}

trap 'emergency_handover' EXIT

# --- phases ----------------------------------------------------------------

phase_preflight() {
  log "node ${SLOT} starting (reason=${NODE_REASON}, run ${GITHUB_RUN_ID:-local})"
  log "work directory: ${WORK_DIR}"

  require_cmd rclone curl jq sha256sum pgrep awk find xargs sort shred

  rclone_configure
  rclone_preflight
  heartbeat_write "starting" 0 0 "$LAST_GOOD_COMMIT"
}

phase_restore() {
  lease_acquire
  restore_from_drive

  # Acknowledge only after the snapshot has been restored *and* verified. The
  # predecessor treats this file as proof that the state now exists in two
  # places, so writing it earlier would let the predecessor shut down on the
  # strength of a restore that has not happened yet.
  if [[ -n "$LAST_GOOD_COMMIT" ]]; then
    local ack
    ack=$(jq -n \
      --arg commit "$LAST_GOOD_COMMIT" \
      --arg slot "$SLOT" \
      --arg reason "$NODE_REASON" \
      --arg hostname "$(hostname)" \
      --argjson run_id "${GITHUB_RUN_ID:-0}" \
      --argjson ack_unix "$(now_unix)" \
      '{commit:$commit, slot:$slot, reason:$reason, hostname:$hostname,
        run_id:$run_id, ack_unix:$ack_unix}')
    printf '%s' "$ack" >"${PIPE_DIR}/ack.json"
    if retry 3 rclone copyto "${PIPE_DIR}/ack.json" \
        "${DRIVE_REMOTE}:${ACK_ROOT}/${LAST_GOOD_COMMIT}.json" >/dev/null 2>&1; then
      log "acknowledged commit ${LAST_GOOD_COMMIT}"
    else
      warn "could not publish the acknowledgement for ${LAST_GOOD_COMMIT}"
    fi
  fi

  heartbeat_write "restored" 0 0 "$LAST_GOOD_COMMIT"
}

phase_start_workload() {
  local tunnel_token="${CF_TUNNEL_TOKEN:-}"
  if [[ -n "$tunnel_token" ]]; then
    log "starting the tunnel connector"
    # The token is passed as an argv argument here because that is the only
    # interface `cloudflared` offers for a remotely-managed tunnel. It is the one
    # credential this design cannot keep out of argv; the mitigation is that the
    # token is scoped to a single tunnel and can be rotated from the Cloudflare
    # dashboard without touching anything else. See docs/SECURITY.md.
    cloudflared tunnel --no-autoupdate run --token "$tunnel_token" \
      >"${PIPE_DIR}/cloudflared.log" 2>&1 &
    TUNNEL_PID=$!
    sleep 5
    if kill -0 "$TUNNEL_PID" 2>/dev/null; then
      log "tunnel connector running (pid ${TUNNEL_PID})"
    else
      warn "the tunnel connector exited immediately; check ${PIPE_DIR}/cloudflared.log"
    fi
  else
    warn "CF_TUNNEL_TOKEN is not set; the static domain will not be bound"
  fi

  local workload="${SCRIPT_DIR}/workload.sh"
  if [[ -x "$workload" ]]; then
    log "starting the workload"
    "$workload" >"${PIPE_DIR}/workload.log" 2>&1 &
    WORKLOAD_PID=$!
    log "workload started (pid ${WORKLOAD_PID})"
  else
    warn "no executable workload at ${workload}; running the gate with no workload"
  fi

  # Give the workload a moment to either come up or die, so the ledger reports
  # reality instead of optimism.
  sleep 10
  heartbeat_write "running" 0 0 "$LAST_GOOD_COMMIT"
}

phase_runtime_gate() {
  local freeze_at=$(( START_UNIX + FREEZE_AT_MINUTES * 60 ))
  local last_heartbeat=$(( $(now_unix) - HEARTBEAT_INTERVAL_SECONDS ))
  local last_killswitch_check=0
  local last_progress=0

  log "entering the runtime gate; freezing at $(date -u -d "@${freeze_at}" '+%H:%M:%SZ')"

  while :; do
    local now
    now=$(now_unix)
    (( now >= freeze_at )) && break

    if (( now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS )); then
      heartbeat_write "running" 0 0 "$LAST_GOOD_COMMIT"
      last_heartbeat=$now
    fi

    # Poll the kill switch every few minutes so an operator can stop a node that
    # is already running, rather than only being able to prevent the next one.
    if (( now - last_killswitch_check >= KILLSWITCH_POLL_SECONDS )); then
      last_killswitch_check=$now
      if killswitch_engaged; then
        log "kill switch engaged; ending this cycle without a handover"
        NODE_REASON="killswitch"
        return 10
      fi
    fi

    if (( now - last_progress >= 1800 )); then
      last_progress=$now
      local remaining=$(( (freeze_at - now) / 60 ))
      log "${remaining} minute(s) remaining in the runtime gate"
      # A supervisor that has died is worth knowing about two hours before the
      # freeze, not at the freeze.
      if [[ -n "$WORKLOAD_PID" ]] && ! kill -0 "$WORKLOAD_PID" 2>/dev/null; then
        warn "the workload process has exited; the node will keep the domain alive until the handover"
      fi
    fi

    sleep 15
  done

  log "runtime gate elapsed"
  return 0
}

phase_snapshot() {
  heartbeat_write "freezing" 0 0 "$LAST_GOOD_COMMIT"
  freeze_workload
  heartbeat_write "frozen" "${#FROZEN_PIDS[@]}" 0 "$LAST_GOOD_COMMIT"
}

phase_backup() {
  # `backup_publish` announces the snapshot path on stdout and logs to stderr;
  # the path is already available as SNAPSHOT_PATH, so the capture is discarded
  # rather than bound to a variable nothing reads.
  if ! backup_publish "$LAST_GOOD_COMMIT" >/dev/null; then
    # backup_publish dies rather than returning, so reaching here means it did
    # not. Left as an explicit guard so a future refactor cannot silently turn a
    # failed backup into a successful cycle.
    warn "snapshot upload failed; continuing with the previous commit"
    return 1
  fi

  LAST_GOOD_COMMIT="$SNAPSHOT_PATH"
  backup_prune
  heartbeat_write "committed" "${#FROZEN_PIDS[@]}" 0 "$LAST_GOOD_COMMIT"
  return 0
}

phase_handover() {
  local ack_timeout_used=0

  # The kill switch is checked immediately before the handover as well: the
  # operator's most likely intent when they flip it is "do not start another
  # node", and that decision should not depend on when they happened to flip it
  # relative to the runtime gate.
  if killswitch_engaged; then
    log "kill switch engaged; snapshot retained, no successor dispatched"
    NODE_REASON="killswitch"
    return 10
  fi

  if ! dispatch_successor "$LAST_GOOD_COMMIT"; then
    warn "handover dispatch failed; the node will stop and the state stays safe on Drive"
    return 11
  fi

  while :; do
    if wait_for_ack "$LAST_GOOD_COMMIT"; then
      HANDOVER_DONE=1
      return 0
    fi

    if (( ack_timeout_used == 0 )); then
      ack_timeout_used=1
      warn "successor did not acknowledge within ${ACK_TIMEOUT_SECONDS}s"
      warn "re-dispatching once and holding the domain for one more window"
      # A second dispatch is safe: the lease makes concurrent successors fail
      # fast rather than corrupt the state. The loser exits non-zero after its
      # lease wait, which is visible in the ledger as a failed run.
      dispatch_successor "$LAST_GOOD_COMMIT" || true
      continue
    fi

    warn "successor still silent; draining anyway (the state is committed on Drive)"
    return 0
  done
}

# --- main ------------------------------------------------------------------

main() {
  parse_args "$@"

  phase_preflight
  phase_restore
  phase_start_workload

  local gate_rc=0
  phase_runtime_gate || gate_rc=$?

  phase_snapshot

  local backup_ok=1
  phase_backup || backup_ok=0

  if (( backup_ok == 0 )); then
    warn "this cycle has no new snapshot; handing over the previous commit"
  fi

  heartbeat_write "handover" "${#FROZEN_PIDS[@]}" 0 "$LAST_GOOD_COMMIT"

  local handover_rc=0
  phase_handover || handover_rc=$?

  case "$handover_rc" in
    0)  log "handover acknowledged; state is held by two nodes" ;;
    10) log "stopped by the kill switch" ;;
    11) warn "no successor was dispatched" ;;
  esac
  (( gate_rc == 10 )) && NODE_REASON="killswitch"

  # Always drain, including on the kill-switch path: the domain should not stay
  # bound to a node the operator has asked to stop.
  drain_workload "$WORKLOAD_PATTERN"
  drain_node "$LAST_GOOD_COMMIT" "$NODE_REASON"

  log "cycle complete (slot ${SLOT}, reason ${NODE_REASON})"
}

main "$@"
