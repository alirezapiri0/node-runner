#!/usr/bin/env bash
#
# Active test workload for Node Runner.
# Tracks state in WORK_DIR/test_state.json across cycle handovers.

set -Eeuo pipefail

WORK_DIR="${WORK_DIR:-${HOME}/work_data}"
STATE_FILE="${WORK_DIR}/test_state.json"

log() { printf '%s [workload] %s\n' "$(date -u '+%H:%M:%S')" "$*"; }

mkdir -p "$WORK_DIR"

runs=1
counter=0

if [[ -f "$STATE_FILE" ]]; then
  runs=$(jq -r '.runs // 1' "$STATE_FILE" 2>/dev/null || echo 1)
  runs=$((runs + 1))
  counter=$(jq -r '.counter // 0' "$STATE_FILE" 2>/dev/null || echo 0)
  log "Found existing state from predecessor! Resuming Run #${runs} from counter ${counter}"
else
  log "Starting fresh test state at Run #${runs}"
fi

checkpoint() {
  local tmp="${STATE_FILE}.tmp.$$"
  jq -n \
    --argjson runs "$runs" \
    --argjson counter "$counter" \
    --argjson checkpoint_unix "$(date -u '+%s')" \
    --arg last_tick "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    '{runs: $runs, counter: $counter, checkpoint_unix: $checkpoint_unix, last_tick: $last_tick}' >"$tmp"
  mv -f "$tmp" "$STATE_FILE"
  log "Checkpoint saved: Run #${runs}, Counter=${counter}"
}

on_term() {
  log "SIGTERM received; flushing final checkpoint for handover"
  checkpoint
  exit 0
}
trap on_term TERM INT

checkpoint

while :; do
  counter=$((counter + 1))
  log "Run #${runs} - Tick #${counter} running on $(hostname)..."
  checkpoint
  sleep 5
done
