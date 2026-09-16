#!/usr/bin/env bash
# shellcheck shell=bash
#
# Shared library for the lifecycle scripts. Sourced, never executed directly.
#
# Ground rules that the rest of the lifecycle depends on:
#
#   * `set -euo pipefail` plus `inherit_errexit` everywhere, so a failure inside
#     a subshell is still a failure.
#   * Secrets arrive through the environment (GitHub injects secrets as env vars)
#     and are never placed in `argv`. On a shared runner, `/proc/<pid>/cmdline`
#     is world-readable while the environment block is not, so anything that
#     takes a credential as an argument is a leak waiting for a second process.
#   * Nothing that touches a credential runs under `set -x`.
#
# The state layout this library addresses, relative to the Drive folder that has
# been shared with the service account:
#
#   heartbeat.json            runner writes (~60s); the desktop app reads it
#   KILLSWITCH.json           the desktop app writes it; this script reads it
#   state/lease.json          writer lease, so two nodes never snapshot together
#   state/COMMIT/<ts>.json    commit record published by the outgoing node
#   state/ACK/<run_id>.json   acknowledgement published by the incoming node
#   snapshots/<ts>/           immutable snapshot directories, newest wins
#   snapshots/<ts>/MANIFEST.sha256

set -Eeuo pipefail
shopt -s inherit_errexit
IFS=$'\n\t'

# --- configuration, all overridable from the workflow ----------------------

# GitHub-hosted runners run as `runner`, not root, and `/root` is not writable
# without sudo. Snapshotting as root would also leave the restored tree owned by
# root, which then breaks the next cycle's `pkill`/write as the unprivileged
# user. The default is therefore under $HOME; the specification's `/root/work_data`
# still works by setting WORK_DIR explicitly on a root-runner.
readonly WORK_DIR="${WORK_DIR:-${HOME}/work_data}"
readonly DRIVE_REMOTE="${DRIVE_REMOTE:-gdrive}"
readonly SNAPSHOT_ROOT="${SNAPSHOT_ROOT:-snapshots}"
readonly STATE_ROOT="${STATE_ROOT:-state}"
readonly HEARTBEAT_FILE="${HEARTBEAT_FILE:-heartbeat.json}"
readonly KILLSWITCH_FILE="${KILLSWITCH_FILE:-KILLSWITCH.json}"

readonly CYCLE_MINUTES="${CYCLE_MINUTES:-340}"
readonly FREEZE_AT_MINUTES="${FREEZE_AT_MINUTES:-325}"
readonly ACK_TIMEOUT_SECONDS="${ACK_TIMEOUT_SECONDS:-180}"
readonly HEARTBEAT_INTERVAL_SECONDS="${HEARTBEAT_INTERVAL_SECONDS:-60}"
readonly BACKUP_RETENTION="${BACKUP_RETENTION:-20}"
readonly WORKLOAD_PATTERN="${WORKLOAD_PATTERN:-}"
readonly WORKFLOW_FILE="${WORKFLOW_FILE:-runner.yml}"
readonly TARGET_REF="${TARGET_REF:-main}"

readonly LOG_TAIL_LINES="${LOG_TAIL_LINES:-40}"
readonly PIPE_DIR="${RUNNER_TEMP:-/tmp}/node-runner"
readonly LOG_FILE="${PIPE_DIR}/lifecycle.log"
readonly SA_FILE="${PIPE_DIR}/service-account.json"

# Guard rails. These are mistakes that are cheap to catch and expensive to
# discover at minute 325.
if (( FREEZE_AT_MINUTES >= CYCLE_MINUTES )); then
  echo "FATAL: FREEZE_AT_MINUTES (${FREEZE_AT_MINUTES}) must be below CYCLE_MINUTES (${CYCLE_MINUTES})" >&2
  exit 2
fi
if (( CYCLE_MINUTES > 345 )); then
  echo "FATAL: CYCLE_MINUTES (${CYCLE_MINUTES}) leaves too little margin under GitHub's 360 minute job limit" >&2
  exit 2
fi

# --- logging ---------------------------------------------------------------

_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

log()  { printf '%s [info]  %s\n' "$(_ts)" "$*" | tee -a "$LOG_FILE" >&2; }
warn() { printf '%s [warn]  %s\n' "$(_ts)" "$*" | tee -a "$LOG_FILE" >&2; }

die() {
  printf '%s [fatal] %s\n' "$(_ts)" "$*" | tee -a "$LOG_FILE" >&2
  exit 1
}

# Log a line without echoing it to the console twice (used by traps).
log_quiet() { printf '%s [info]  %s\n' "$(_ts)" "$*" >>"$LOG_FILE"; }

require_cmd() {
  local missing=0
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      printf 'FATAL: required command not found: %s\n' "$cmd" >&2
      missing=1
    fi
  done
  (( missing == 0 )) || exit 3
}

# Retry a command with bounded exponential backoff. Used for every network
# operation that is not idempotent by construction, because a transient 5xx
# during the freeze window would otherwise cost an entire cycle's state.
retry() {
  local attempts="$1"; shift
  local delay=2
  local n=0
  while :; do
    if "$@"; then
      return 0
    fi
    n=$((n + 1))
    if (( n >= attempts )); then
      warn "command failed after ${attempts} attempts: $*"
      return 1
    fi
    warn "attempt ${n}/${attempts} failed for '$1', retrying in ${delay}s"
    sleep "$delay"
    delay=$((delay * 2))
    (( delay > 30 )) && delay=30
  done
}

# --- rclone ----------------------------------------------------------------

# Configure rclone entirely from the environment.
#
# `rclone.conf` is never written to disk: the service-account path, the scope and
# the root folder all come from RCLONE_CONFIG_* variables. That removes a file
# that would otherwise hold a credential path and would need shreading at the
# end of every cycle.
rclone_configure() {
  [[ -n "${RCLONE_SERVICE_ACCOUNT_JSON:-}" ]] || die "RCLONE_SERVICE_ACCOUNT_JSON is not set"

  mkdir -p "$PIPE_DIR"
  umask 077
  printf '%s' "$RCLONE_SERVICE_ACCOUNT_JSON" >"$SA_FILE"
  chmod 600 "$SA_FILE"

  export RCLONE_CONFIG="${PIPE_DIR}/rclone.conf"
  export RCLONE_CONFIG_GDRIVE_TYPE="drive"
  export RCLONE_CONFIG_GDRIVE_SCOPE="drive"
  export RCLONE_CONFIG_GDRIVE_SERVICE_ACCOUNT_FILE="$SA_FILE"
  # Uploads are not resumable across a job restart, so fail fast rather than
  # hanging: this is what the `--timeout`/`--contimeout` pair below achieves.
  export RCLONE_CONFIG_GDRIVE_ROOT_FOLDER_ID="${GDRIVE_ROOT_FOLDER_ID:-}"
  export RCLONE_DRIVE_CHUNK_SIZE="64M"
  export RCLONE_TRANSFERS="8"
  export RCLONE_CHECKERS="16"
  export RCLONE_FAST_LIST="true"
  # A single retry storm inside the freeze window is worse than an immediate
  # failure, which the trap can still turn into an emergency snapshot.
  export RCLONE_RETRIES="3"
  export RCLONE_LOW_LEVEL_RETRIES="6"
  export RCLONE_STATS="15s"
  export RCLONE_LOG_LEVEL="INFO"
  export RCLONE_USE_JSON_LOG="false"
}

# Preflight the credential before anything is written. Failing here costs
# seconds; failing at the upload costs the cycle.
rclone_preflight() {
  log "checking Drive access with the service account"
  if ! retry 3 rclone about "${DRIVE_REMOTE}:" >/dev/null 2>"${PIPE_DIR}/rclone-about.err"; then
    local detail
    detail=$(tr -d '\r' <"${PIPE_DIR}/rclone-about.err" | tail -n 5)
    # The overwhelmingly common cause is that the target folder was never shared
    # with the service account, so say that rather than echoing a raw 404.
    die "cannot use the Drive remote. Most often this means the backup folder has not been shared with the service account (${detail})"
  fi
}

# Shred the on-disk copy of the service-account key.
scrub_credentials() {
  if [[ -f "$SA_FILE" ]]; then
    shred -u "$SA_FILE" 2>/dev/null || rm -f "$SA_FILE"
  fi
  rm -f "${PIPE_DIR}/rclone.conf" 2>/dev/null || true
  # Secrets are unset from this process's environment so that any later command,
  # including one in an error trap, cannot inherit them.
  unset RCLONE_SERVICE_ACCOUNT_JSON CF_TUNNEL_TOKEN GH_PAT 2>/dev/null || true
}

# --- Unix time -------------------------------------------------------------

now_unix() { date -u '+%s'; }

# --- heartbeats ------------------------------------------------------------

# Write the liveness record the desktop app reads.
#
# This is also the "live log" channel: GitHub's API only serves run logs after a
# run finishes, so there is no way to stream them, and relaying a bounded tail
# here is the only mechanism that actually works. The tail is filtered for
# anything that looks like a credential before it leaves the machine.
heartbeat_write() {
  local phase="$1"
  local frozen_pids="${2:-0}"
  local bytes="${3:-0}"
  local commit="${4:-}"

  local tail_json='[]'
  if [[ -f "$LOG_FILE" ]]; then
    tail_json=$(
      tail -n "$LOG_TAIL_LINES" "$LOG_FILE" \
        | sed -E 's/(gh[pousr]_[A-Za-z0-9]{16,})/[redacted-token]/g;
                  s/(Bearer )[A-Za-z0-9._-]{16,}/\1[redacted]/g;
                  s/("private_key" *: *")[^"]{8,}/\1[redacted]/g' \
        | jq -R -s 'split("\n") | map(select(length > 0))'
    )
  fi

  local payload
  payload=$(jq -n \
    --arg phase "$phase" \
    --arg slot "${SLOT:-?}" \
    --arg hostname "$(hostname)" \
    --arg commit "$commit" \
    --argjson run_id "${GITHUB_RUN_ID:-0}" \
    --argjson heartbeat_unix "$(now_unix)" \
    --argjson frozen_pids "$frozen_pids" \
    --argjson bytes_uploaded "$bytes" \
    --argjson log_tail "$tail_json" \
    '{phase:$phase, slot:$slot, hostname:$hostname, commit:$commit, run_id:$run_id,
      heartbeat_unix:$heartbeat_unix, frozen_pids:$frozen_pids,
      bytes_uploaded:$bytes_uploaded, log_tail:$log_tail}')

  printf '%s' "$payload" >"${PIPE_DIR}/heartbeat.json"
  # Heartbeat failures are never fatal: losing the operator's view of a healthy
  # node is annoying, killing a healthy node because telemetry failed is worse.
  if ! retry 2 rclone copyto "${PIPE_DIR}/heartbeat.json" \
      "${DRIVE_REMOTE}:${HEARTBEAT_FILE}" >/dev/null 2>&1; then
    warn "could not publish the heartbeat (continuing)"
  fi
}

# --- kill switch -----------------------------------------------------------

# True when the operator has engaged the stop switch.
#
# Read before the handover rather than cached at startup: the marker is meant to
# be able to stop a loop that is already running.
killswitch_engaged() {
  local raw
  if ! raw=$(retry 2 rclone cat "${DRIVE_REMOTE}:${KILLSWITCH_FILE}" 2>/dev/null); then
    return 1
  fi
  [[ "$(printf '%s' "$raw" | jq -r '.engaged // false' 2>/dev/null)" == "true" ]]
}

# --- GitHub ----------------------------------------------------------------

# Call the REST API with the token supplied on stdin.
#
# `curl --config -` is what keeps the credential out of `argv`. Passing it as
# `-H "Authorization: Bearer $GH_PAT"` would expose it to any process that can
# read `/proc/<pid>/cmdline`, which is every process on the machine.
gh_api() {
  local method="$1" path="$2" body="${3:-}"
  [[ -n "${GH_PAT:-}" ]] || die "GH_PAT is not set"

  local -a args=(
    --silent --show-error --fail-with-body
    --request "$method"
    --header "Accept: application/vnd.github+json"
    --header "X-GitHub-Api-Version: 2022-11-28"
    --retry 3 --retry-all-errors --retry-delay 2
    --url "https://api.github.com${path}"
  )
  if [[ -n "$body" ]]; then
    args+=(--header "Content-Type: application/json" --data "$body")
  fi

  printf 'header = "Authorization: Bearer %s"\n' "$GH_PAT" | curl --config - "${args[@]}"
}
