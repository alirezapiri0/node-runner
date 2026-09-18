/**
 * Mirrors of the Rust DTOs in `src-tauri/src/`.
 *
 * Kept deliberately narrow. Note what is *absent*: there is no type for a secret
 * value anywhere in this file, because no command returns one. The frontend can
 * write secrets and list their metadata, and that is the entire surface.
 */

export interface KdfParams {
  m_cost_kib: number;
  t_cost: number;
  p_cost: number;
}

export type ProtectorStatus = "Healthy" | "ProtectionChanged" | "Failing" | "Unsupported";

export interface SecretView {
  name: string;
  created_at_unix: number;
  rotated_at_unix: number | null;
  note: string | null;
}

export interface TamperEvent {
  at_unix: number;
  detail: string;
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  secrets: SecretView[];
  protector: ProtectorStatus;
  swap_protection: boolean;
  format: string | null;
  kdf: KdfParams | null;
  os_wrap: boolean;
  binding_label: string | null;
  tamper_strikes: number;
  tamper_log: TamperEvent[];
  rotate_count: number;
  recoverable_from_backup: boolean;
  unlocked_secs: number | null;
  auto_lock_secs: number | null;
}

export interface Config {
  owner: string;
  repo: string;
  workflow_file: string;
  cycle_minutes: number;
  poll_seconds: number;
  auto_lock_minutes: number;
  workload_pattern: string;
  tunnel_hostname: string;
  drive_folder_id: string;
  backup_retention: number;
}

export interface NodeStatus {
  phase: string;
  slot: string;
  run_id: number | null;
  run_url: string | null;
  started_at_unix: number | null;
  remaining_secs: number | null;
  elapsed_secs: number | null;
  conclusion: string | null;
  kill_switch: boolean;
  last_poll_unix: number | null;
  next_poll_secs: number | null;
  rate_limit_remaining: number | null;
  error: string | null;
}

export interface KillSwitchState {
  engaged: boolean;
  drive_marker_written: boolean;
  detail: string;
}

export interface DispatchReport {
  accepted: boolean;
  target_slot: string;
  detail: string;
}

export interface SecretReport {
  name: string;
  ok: boolean;
  detail: string;
}

export interface DriveEntry {
  id: string;
  name: string;
  modified_unix: number | null;
  size: number | null;
  is_folder: boolean;
}

export interface Heartbeat {
  run_id: number | null;
  slot: string;
  phase: string;
  hostname: string;
  commit: string;
  heartbeat_unix: number | null;
  frozen_pids: number;
  bytes_uploaded: number | null;
  log_tail: string[];
}

export interface LogTail {
  next_seq: number;
  lines: string[];
}

export interface AppInfo {
  version: string;
  data_dir: string;
  vault_path: string;
  swap_protection: boolean;
  os_protection: boolean;
  protector_status: string;
  secret_fingerprint_helper: boolean;
}

/** Credentials the runner expects, mirrored from `gh::secrets::REQUIRED_SECRETS`. */
export interface RequiredSecret {
  name: string;
  purpose: string;
  /** Whether a value may be pasted as multi-line (a service-account JSON file). */
  multiline: boolean;
}

export const REQUIRED_SECRETS: RequiredSecret[] = [
  {
    name: "GH_PAT",
    purpose:
      "توکن دسترسی گیت‌هاب (GitHub PAT) — برای ایجاد و ادامه حتمی هاستینگ روی جاب بعدی در گیت‌هاب اکشن. نیاز به دسترسی Actions (خواندن و نوشتن) و Contents (خواندن).",
    multiline: false,
  },
  {
    name: "RCLONE_SERVICE_ACCOUNT_JSON",
    purpose:
      "کلید حساب سرویس گوگل درایو (Service Account JSON) — جهت ذخیره، اسنپ‌شات و بازیابی مداوم داده‌های هاستینگ بین جاب‌های اکشن در گوگل درایو.",
    multiline: true,
  },
  {
    name: "CF_TUNNEL_TOKEN",
    purpose:
      "توکن تانل کلودفلر (Cloudflare Tunnel) — اتصال دائمی دامنه شما به جاب اکشن تا در طول جابجایی و تداوم هاستینگ، دامنه پایدار بماند.",
    multiline: false,
  },
];
