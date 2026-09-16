#!/usr/bin/env bash
# shellcheck shell=bash
#
# Handover to the successor node.
#
# This is where the implementation departs furthest from the specification, and
# where it matters most.
#
# The specification's handover creates a new public repository every cycle and
# injects a repository-creation-scoped PAT, the service-account key and the
# tunnel token into it. That design has two problems, one of which is not
# fixable by writing better code:
#
#   1. It puts the operator's most privileged credential (repo creation, plus
#      whatever else the PAT can reach) inside a public repository's secret
#      store, freshly, every 5 hours 40 minutes, forever. GitHub repo secrets
#      are write-only to the API, but that is a much weaker guarantee than the
#      credential never being there at all. The blast radius is the whole
#      account, not one repository.
#   2. Using Actions as perpetual general-purpose compute via self-replicating
#      repositories runs against GitHub's Acceptable Use Policies. The failure
#      mode is account suspension — not a crash you can debug, but an account
#      you no longer have. A suspension takes your repositories, your issues and
#      (depending on the plan) your ability to restore any of it with it.
#
# So: one long-lived **private** repository, and the predecessor triggers the
# successor run through the workflow-dispatch API. The secrets are already
# configured on that repository by the operator, so no credential is ever copied
# anywhere. The PAT used here needs `actions:write` on one repository — not repo
# creation, and nothing account-wide.
#
# The one requirement this has that the spec's design did not: the successor
# must be able to start while the predecessor is still alive, because the 6-hour
# job ceiling is per-job, not per-node. Dispatch, confirm, then exit.

readonly ACK_ROOT="${STATE_ROOT}/ACK"

# Slot ping-pong: the successor always takes the other slot, so a stuck or
# half-dispatched node never reuses the slot name the operator is currently
# looking at.
successor_slot() {
  case "${SLOT:-blue}" in
    blue) printf 'green' ;;
    green) printf 'blue' ;;
    *) printf 'blue' ;;
  esac
}

dispatch_successor() {
  local commit="$1"
  local next_slot
  next_slot=$(successor_slot)

  log "handing over to slot '${next_slot}' at commit ${commit}"

  local body
  body=$(jq -n \
    --arg slot "$next_slot" \
    --arg commit "$commit" \
    --arg reason "${NODE_REASON:-cycle}" \
    --arg origin "${GITHUB_RUN_ID:-0}" \
    '{ref:null, inputs:{slot:$slot, commit:$commit, reason:$reason, origin_run:$origin}}' \
    | jq --arg ref "$TARGET_REF" '.ref = $ref')

  # The run URL and the response body are logged; the PAT is not, because
  # gh_api feeds it to curl on stdin rather than through `argv`.
  if ! gh_api POST "/repos/${GITHUB_REPOSITORY}/actions/workflows/${WORKFLOW_FILE}/dispatches" "$body" \
      >"${PIPE_DIR}/dispatch.out" 2>"${PIPE_DIR}/dispatch.err"; then
    local detail
    detail=$(tr -d '\r' <"${PIPE_DIR}/dispatch.err" | tail -n 3)
    warn "workflow dispatch failed: ${detail}"
    return 1
  fi

  log "successor dispatched (slot ${next_slot}); awaiting acknowledgement"
  return 0
}

# Wait for the successor to confirm it has restored the commit we just
# published.
#
# This is the difference between a handover and a hope. Dispatching a workflow
# proves only that a YAML file was accepted by the API; the successor does not
# write its ACK until it has acquired the lease, restored the snapshot,
# *verified it against the manifest*, and started the workload. Only then is it
# true that the state is safely held by two nodes and this one can stop.
wait_for_ack() {
  local commit="$1"
  local deadline=$(( $(now_unix) + ACK_TIMEOUT_SECONDS ))

  while :; do
    local raw
    if raw=$(retry 1 rclone cat "${DRIVE_REMOTE}:${ACK_ROOT}/${commit}.json" 2>/dev/null); then
      if [[ "$(printf '%s' "$raw" | jq -r '.commit // empty' 2>/dev/null)" == "$commit" ]]; then
        log "successor acknowledged commit ${commit} (run $(printf '%s' "$raw" | jq -r '.run_id'))"
        return 0
      fi
    fi

    if (( $(now_unix) >= deadline )); then
      return 1
    fi

    # Renew while waiting: from the successor's point of view this process is
    # still the owner and still alive, and an unrenewed lease during a slow
    # handover would invite it to break a lease that should not be broken.
    lease_renew >/dev/null 2>&1 || true
    heartbeat_write "awaiting_ack" 0 0 "$commit" >/dev/null 2>&1 || true
    sleep 10
  done
}
