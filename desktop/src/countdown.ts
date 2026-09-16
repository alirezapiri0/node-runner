/**
 * Countdown rendering.
 *
 * The value itself is authoritative in Rust: it is derived from GitHub's own
 * `run_started_at` plus the configured cycle length, and pushed to the UI. This
 * module only formats and animates what it is handed, and never counts down on
 * its own. That is deliberate -- a locally ticking timer drifts, and worse, it
 * keeps counting down through a laptop sleep while the node has actually been
 * replaced, which would show a confidently wrong number.
 */

const RING_RADIUS = 58;
const CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

export interface CountdownView {
  /** Seconds remaining, or null when there is no active run. */
  remaining: number | null;
  /** Total cycle length in seconds, for the ring fraction. */
  cycleSeconds: number;
  /** Slot label ("a", "b", or "?"). */
  slot: string;
  /** GitHub run status, already humanised. */
  phase: string;
  startedUnix: number | null;
  elapsedSeconds: number | null;
  runUrl: string | null;
}

/** `HH:MM:SS`, or `--:--:--` when unknown. */
export function formatDuration(totalSeconds: number | null): string {
  if (totalSeconds === null || totalSeconds < 0 || !Number.isFinite(totalSeconds)) {
    return "--:--:--";
  }
  const secs = Math.floor(totalSeconds);
  const hours = Math.floor(secs / 3600);
  const minutes = Math.floor((secs % 3600) / 60);
  const seconds = secs % 60;
  return [hours, minutes, seconds]
    .map((part) => String(part).padStart(2, "0"))
    .join(":");
}

/** Ring stroke colour banding, so the end of a cycle looks urgent. */
export function urgencyClass(remaining: number | null, cycleSeconds: number): string {
  if (remaining === null || cycleSeconds <= 0) {
    return "";
  }
  const fraction = remaining / cycleSeconds;
  if (fraction <= 0.03) {
    return "is-critical";
  }
  if (fraction <= 0.1) {
    return "is-low";
  }
  return "";
}

/** Dash offset for the progress ring: 0 = empty, full circumference = full. */
export function ringDashOffset(remaining: number | null, cycleSeconds: number): number {
  if (remaining === null || cycleSeconds <= 0) {
    return CIRCUMFERENCE;
  }
  const fraction = Math.max(0, Math.min(1, remaining / cycleSeconds));
  return CIRCUMFERENCE * (1 - fraction);
}

export const RING = { radius: RING_RADIUS, circumference: CIRCUMFERENCE };

/** Compact "3m ago" style relative time for ledgers and heartbeats. */
export function relativeTime(unixSeconds: number | null): string {
  if (unixSeconds === null) {
    return "unknown";
  }
  const delta = Math.floor(Date.now() / 1000) - unixSeconds;
  if (delta < 0) {
    return "in the future";
  }
  if (delta < 10) {
    return "just now";
  }
  if (delta < 60) {
    return `${delta}s ago`;
  }
  if (delta < 3600) {
    return `${Math.floor(delta / 60)}m ago`;
  }
  if (delta < 86400) {
    return `${Math.floor(delta / 3600)}h ago`;
  }
  return `${Math.floor(delta / 86400)}d ago`;
}

/** Byte counts for the backup ledger. */
export function formatBytes(bytes: number | null): string {
  if (bytes === null || bytes < 0) {
    return "--";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}
