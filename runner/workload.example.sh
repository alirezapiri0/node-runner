#!/usr/bin/env bash
#
# Reference workload.
#
# Copy this to runner/workload.sh and replace the body with whatever the node is
# meant to compute. The lifecycle script starts it in the background, freezes it
# with SIGSTOP at the freeze point, and later SIGTERMs it during the drain.
#
# Two rules make a workload a good citizen of this architecture:
#
#   1. Handle SIGTERM by flushing and exiting, and do it quickly. The drain grace
#      period is 45 seconds; a workload that needs longer will be SIGKILLed, and
#      anything it had in memory is lost.
#   2. Keep all durable state inside WORK_DIR and nowhere else. Anything written
#      outside it is not snapshotted, so it disappears when the node is replaced
#      — which is every 5 hours 40 minutes, by design.
#
# The `--checkpoint` mode below is the pattern worth copying: because the
# lifecycle freezes the process rather than terminating it, a workload can
# snapshot itself *at the freeze point* with full knowledge of its own consistency
# invariants, which no external snapshotter can do.

set -Eeuo pipefail

WORK_DIR="${WORK_DIR:-${HOME}/work_data}"
STATE_FILE="${WORK_DIR}/.workload-state.json"

log() { printf '%s [workload] %s\n' "$(date -u '+%H:%M:%S')" "$*"; }

checkpoint() {
  # Called on the SIGSTOP path indirectly, and directly on SIGTERM. Writing
  # through a temporary file and renaming means a checkpoint written at the same
  # moment as the freeze is either wholly present or wholly absent, never torn.
  local tmp="${STATE_FILE}.tmp.$$"
  printf '{"checkpoint_unix":%s,"pid":%s}\n' "$(date -u '+%s')" "$$" >"$tmp"
  mv -f "$tmp" "$STATE_FILE"
  log "checkpoint written"
}

on_term() {
  log "SIGTERM received; flushing"
  checkpoint
  exit 0
}
trap on_term TERM INT

mkdir -p "$WORK_DIR"
log "workload starting; state lives in ${WORK_DIR}"

tick=0
while :; do
  tick=$((tick + 1))
  date -u '+%Y-%m-%dT%H:%M:%SZ workload tick '"$tick" >>"${WORK_DIR}/workload.log"
  # Replace this with real work. The loop exists so the process stays alive and
  # observable, which is what the freeze and drain logic act on.
  sleep 30
done
