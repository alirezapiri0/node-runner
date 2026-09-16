#!/usr/bin/env bash
# shellcheck shell=bash
#
# Crash-consistent freeze of the workload.
#
# The specification asks for `pkill -STOP`. That is the right primitive, and the
# reason is worth stating: SIGTERM would let the workload shut down *and* would
# make the snapshot unrecoverable, because a terminated process cannot be
# resumed if the upload fails and the cycle has to be retried. SIGSTOP suspends
# execution without unwinding anything, so a failed backup can be retried
# against a still-frozen, still-consistent tree.

# Suspended PIDs, so the drain step can resume exactly what was frozen rather
# than pattern-matching again against a moving target.
FROZEN_PIDS=()

wait_for_dirty_pages() {
  # `sync` returns once writeback has been *queued*, not once it has landed.
  # Reading /proc/meminfo until the dirty and writeback counters are quiet is
  # what makes the subsequent hash describe the bytes that are actually on disk.
  # On a busy workload these can genuinely take tens of seconds.
  local deadline=$(( $(now_unix) + ${DIRTY_WAIT_SECONDS:-90} ))
  local dirty writeback

  while :; do
    dirty=$(awk '/^Dirty:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    writeback=$(awk '/^Writeback:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)

    if (( dirty < 4096 && writeback < 2048 )); then
      log "filesystem quiesced (dirty=${dirty}KiB writeback=${writeback}KiB)"
      return 0
    fi
    if (( $(now_unix) >= deadline )); then
      # Not fatal. The data is still recoverable, it just may not be perfectly
      # crash-consistent, and refusing to back up at all would be strictly worse.
      warn "dirty pages still present after ${DIRTY_WAIT_SECONDS:-90}s (dirty=${dirty}KiB); snapshotting anyway"
      return 0
    fi
    sleep 1
  done
}

freeze_workload() {
  FROZEN_PIDS=()

  if [[ -z "$WORKLOAD_PATTERN" ]]; then
    warn "WORKLOAD_PATTERN is empty; only the filesystem will be flushed"
    sync
    wait_for_dirty_pages
    return 0
  fi

  mapfile -t pids < <(pgrep -f -- "$WORKLOAD_PATTERN" 2>/dev/null || true)

  # Exclude ourselves and the logging pipeline: a workload pattern broad enough
  # to be useful (`node`, `python`) can otherwise match this script's own
  # command line, freezing the backup halfway through.
  local pid
  for pid in "${pids[@]}"; do
    [[ "$pid" == "$$" ]] && continue
    [[ "$pid" == "$PPID" ]] && continue
    FROZEN_PIDS+=("$pid")
  done

  if (( ${#FROZEN_PIDS[@]} == 0 )); then
    warn "no processes matched '${WORKLOAD_PATTERN}'"
    sync
    wait_for_dirty_pages
    return 0
  fi

  log "suspending ${#FROZEN_PIDS[@]} process(es) matching '${WORKLOAD_PATTERN}'"
  for pid in "${FROZEN_PIDS[@]}"; do
    kill -STOP "$pid" 2>/dev/null || warn "could not suspend pid ${pid}"
  done

  # The kernel will not write back the dirty pages of a stopped process on its
  # own schedule, so ask explicitly and then wait for it to finish.
  sync
  wait_for_dirty_pages
  sync

  log "workload frozen and filesystem flushed"
}

# Resume suspended processes. Called on the drain path, and also on any failure
# path where the snapshot did not happen: a node that gives up on its backup
# should at least hand its workload back to the operator in a running state.
thaw_workload() {
  local pid
  for pid in "${FROZEN_PIDS[@]:-}"; do
    [[ -n "$pid" ]] || continue
    kill -CONT "$pid" 2>/dev/null || true
  done
  if (( ${#FROZEN_PIDS[@]} > 0 )); then
    log "resumed ${#FROZEN_PIDS[@]} suspended process(es)"
  fi
  FROZEN_PIDS=()
}
