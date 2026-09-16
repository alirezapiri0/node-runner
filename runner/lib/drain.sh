#!/usr/bin/env bash
# shellcheck shell=bash
#
# Tear the node down without losing anything.
#
# Ordering is the whole content of this file. Each step exists because doing it
# in the other order loses something:
#
#   1. Thaw, then SIGTERM, then SIGKILL after a grace period. A SIGKILL on a
#      still-frozen process is safe for the snapshot (it is already on Drive)
#      but can leave locks and temp files behind for the successor.
#   2. Stop the tunnel connector last among the processes, so the domain has a
#      live connector for as long as possible. Cloudflare load-balances across
#      connectors of the same tunnel, so during the overlap both nodes serve.
#   3. Scrub the service-account key and unset the secrets, before releasing the
#      lease: a successor that starts while this node still holds a plaintext key
#      on disk is a needless exposure window.
#   4. Release the lease last. The successor waits on it, so releasing early
#      would let it begin restoring while this node is still shutting down.

readonly DRAIN_GRACE_SECONDS="${DRAIN_GRACE_SECONDS:-45}"

drain_workload() {
  local pattern="$1"

  if [[ -z "$pattern" ]]; then
    log "no workload pattern configured; nothing to drain"
    return 0
  fi

  # Resume first. Terminating a SIGSTOPped process works, but a workload that
  # catches SIGTERM to flush its own buffers never gets the chance while frozen,
  # and a clean shutdown is worth a second of overlap.
  thaw_workload

  mapfile -t pids < <(pgrep -f -- "$pattern" 2>/dev/null || true)
  local pid
  local live=()
  for pid in "${pids[@]}"; do
    [[ "$pid" == "$$" ]] && continue
    [[ "$pid" == "$PPID" ]] && continue
    live+=("$pid")
  done

  if (( ${#live[@]} == 0 )); then
    log "workload is already gone"
    return 0
  fi

  log "stopping ${#live[@]} process(es) (SIGTERM)"
  for pid in "${live[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done

  local deadline=$(( $(now_unix) + DRAIN_GRACE_SECONDS ))
  while (( $(now_unix) < deadline )); do
    local remaining=0
    for pid in "${live[@]}"; do
      kill -0 "$pid" 2>/dev/null && remaining=$((remaining + 1))
    done
    (( remaining == 0 )) && break
    sleep 1
  done

  for pid in "${live[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      warn "pid ${pid} ignored SIGTERM after ${DRAIN_GRACE_SECONDS}s; sending SIGKILL"
      kill -KILL "$pid" 2>/dev/null || true
    fi
  done

  log "workload drained"
}

stop_tunnel() {
  if ! pgrep -x cloudflared >/dev/null 2>&1; then
    return 0
  fi
  log "stopping the tunnel connector"
  pkill -TERM -x cloudflared 2>/dev/null || true

  local deadline=$(( $(now_unix) + 20 ))
  while (( $(now_unix) < deadline )); do
    pgrep -x cloudflared >/dev/null 2>&1 || break
    sleep 1
  done
  pkill -KILL -x cloudflared 2>/dev/null || true
}

drain_node() {
  local commit="${1:-}"
  local reason="${2:-cycle}"

  stop_tunnel

  heartbeat_write "handover_complete" 0 0 "$commit" >/dev/null 2>&1 || true

  # The tunnel token is only needed by the process that has already been
  # stopped, so drop it before the slow steps rather than after.
  unset CF_TUNNEL_TOKEN 2>/dev/null || true

  scrub_credentials
  lease_release

  log "node ${SLOT:-?} drained (${reason}); the successor owns the state"
}
