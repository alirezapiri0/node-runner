/**
 * A stand-in for the Tauri command layer.
 *
 * The backend needs the MSVC toolchain, WebView2 and a Tauri host process, so
 * without this file the only way to look at the interface is to build and run the
 * whole application. That is a slow loop for a CSS change and, worse, it keeps a
 * rendering bug invisible until the binary is already in someone's hands -- which
 * is precisely how a blank Settings panel survived a clean typecheck, a clean
 * lint and a green CI run.
 *
 * Nothing in `src/` imports this file and Vite never bundles it: it is reachable
 * only from `dev/harness.html`, which is a development entry point.
 */

import type {
  AppInfo,
  Config,
  DriveEntry,
  Heartbeat,
  KdfParams,
  NodeStatus,
  SecretReport,
  VaultStatus,
} from "../src/types";

const now = (): number => Math.floor(Date.now() / 1000);

const KDF: KdfParams = { m_cost_kib: 262_144, t_cost: 3, p_cost: 4 };

const VAULT: VaultStatus = {
  exists: true,
  unlocked: true,
  secrets: [
    {
      name: "GH_PAT",
      created_at_unix: now() - 86_400,
      rotated_at_unix: null,
      note: "fine-grained, Actions + Secrets only",
    },
    {
      name: "RCLONE_SERVICE_ACCOUNT_JSON",
      created_at_unix: now() - 86_100,
      rotated_at_unix: null,
      note: null,
    },
  ],
  protector: "Healthy",
  swap_protection: true,
  format: "NRVAULT1 (Argon2id + AES-256-GCM)",
  kdf: KDF,
  os_wrap: true,
  binding_label: "Windows DPAPI (current user profile)",
  tamper_strikes: 0,
  tamper_log: [],
  rotate_count: 1,
  recoverable_from_backup: false,
  unlocked_secs: 42,
  auto_lock_secs: 900,
};

const CONFIG: Config = {
  owner: "alirezapiri0",
  repo: "node-runner",
  workflow_file: "runner.yml",
  cycle_minutes: 340,
  poll_seconds: 30,
  auto_lock_minutes: 15,
  workload_pattern: "workload\\.sh",
  tunnel_hostname: "node.example.com",
  drive_folder_id: "1AbCdEfGhIjKlMnOpQrStUvWxYz012345",
  backup_retention: 20,
};

const STATUS: NodeStatus = {
  phase: "in_progress",
  slot: "blue",
  run_id: 35146676018,
  run_url: "https://github.com/alirezapiri0/node-runner/actions/runs/35146676018",
  started_at_unix: now() - 3_600,
  remaining_secs: 300 * 60,
  elapsed_secs: 3_600,
  conclusion: null,
  kill_switch: false,
  last_poll_unix: now() - 4,
  next_poll_secs: 26,
  rate_limit_remaining: 4_987,
  error: null,
};

const INFO: AppInfo = {
  version: "0.1.0",
  data_dir: "%APPDATA%\\dev.noderunner.desktop",
  vault_path: "%APPDATA%\\dev.noderunner.desktop\\vault.nrv",
  swap_protection: true,
  os_protection: true,
  protector_status: "Healthy",
  secret_fingerprint_helper: true,
};

const LEDGER: DriveEntry[] = [
  {
    id: "1snap-0003",
    name: "20260917T031500Z",
    modified_unix: now() - 5_400,
    size: 41_943_808,
    is_folder: true,
  },
  {
    id: "1snap-0002",
    name: "20260916T210000Z",
    modified_unix: now() - 45_000,
    size: 41_902_080,
    is_folder: true,
  },
  {
    id: "commit-0002",
    name: "COMMIT/20260916T210000Z.json",
    modified_unix: now() - 44_900,
    size: 1_204,
    is_folder: false,
  },
];

const HEARTBEAT: Heartbeat = {
  run_id: 35146676018,
  slot: "blue",
  phase: "serving",
  hostname: "node.example.com",
  commit: "snapshots/20260917T031500Z",
  heartbeat_unix: now() - 12,
  frozen_pids: 0,
  bytes_uploaded: 41_943_808,
  log_tail: [
    "node blue starting (reason=cycle, run 35146676018)",
    "restored commit snapshots/20260917T031500Z (41 MiB)",
    "tunnel connector registered for node.example.com",
    "workload matched 1 process (workload.sh)",
    "heartbeat published",
  ],
};

const INVOKE_DELAY_MS = 40;

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  // A little latency on purpose: a UI that only works when the command layer
  // answers instantly is a UI that has not been tested.
  await new Promise((resolve) => setTimeout(resolve, INVOKE_DELAY_MS));

  switch (cmd) {
    case "vault_status":
      return { ...VAULT } as T;
    case "vault_calibrate":
      return { ...KDF } as T;
    case "vault_init":
    case "vault_unlock":
    case "vault_unlock_os":
      return { ...VAULT } as T;
    case "vault_lock":
      return { ...VAULT, unlocked: false, unlocked_secs: null } as T;
    case "vault_set_secret": {
      const name = String(args?.["name"] ?? "UNKNOWN");
      return {
        ...VAULT,
        secrets: [
          ...VAULT.secrets.filter((secret) => secret.name !== name),
          {
            name,
            created_at_unix: now(),
            rotated_at_unix: null,
            note: (args?.["note"] as string | undefined) ?? null,
          },
        ],
      } as T;
    }
    case "vault_delete_secret": {
      const name = String(args?.["name"] ?? "");
      return { ...VAULT, secrets: VAULT.secrets.filter((s) => s.name !== name) } as T;
    }
    case "vault_rotate":
    case "vault_clear_alerts":
      return { ...VAULT, tamper_strikes: 0, tamper_log: [] } as T;
    case "vault_destroy":
      return { exists: false, unlocked: false, secrets: [] } as T;

    case "config_get":
      return { ...CONFIG } as T;
    case "config_set":
      return { ...CONFIG, ...(args?.["config"] as Partial<Config> | undefined) } as T;

    case "node_status":
      return statusSnapshot() as T;
    case "node_set_kill_switch": {
      engaged = Boolean(args?.["engaged"]);
      return {
        engaged,
        drive_marker_written: engaged,
        detail: engaged
          ? "the stop switch is engaged; the marker is written to Drive"
          : "the stop switch is released",
      } as T;
    }
    case "node_dispatch": {
      const next = STATUS.slot === "blue" ? "green" : "blue";
      STATUS.slot = next;
      STATUS.started_at_unix = now();
      STATUS.remaining_secs = CONFIG.cycle_minutes * 60;
      STATUS.elapsed_secs = 0;
      return {
        accepted: true,
        target_slot: next,
        detail: `dispatched ${CONFIG.workflow_file} to slot ${next} on main`,
      } as T;
    }
    case "secrets_inject":
      return [
        { name: "GH_PAT", ok: true, detail: "stored (sealed box, key id 3380204)" },
        { name: "RCLONE_SERVICE_ACCOUNT_JSON", ok: true, detail: "stored (sealed box)" },
        { name: "CF_TUNNEL_TOKEN", ok: true, detail: "stored (sealed box)" },
      ] satisfies SecretReport[] as T;

    case "drive_ledger":
      return LEDGER.map((entry) => ({ ...entry })) as T;
    case "drive_heartbeat":
      return { ...HEARTBEAT } as T;

    case "app_info":
      return { ...INFO } as T;

    case "logs_clear":
      return undefined as T;

    default:
      throw new Error(`the dev harness does not implement \`${cmd}\``);
  }
}

let engaged = false;
let logSeq = 0;

/** Node status, as the real poller would report it a moment ago. */
function statusSnapshot(): NodeStatus {
  const drift = now() - (STATUS.last_poll_unix ?? now());
  return {
    ...STATUS,
    kill_switch: engaged,
    last_poll_unix: now() - 4,
    remaining_secs: STATUS.remaining_secs === null ? null : Math.max(0, STATUS.remaining_secs - drift),
    elapsed_secs: STATUS.elapsed_secs === null ? null : STATUS.elapsed_secs + drift,
  };
}

const LOG_LINES = [
  "lifecycle: preflight ok (rclone, cloudflared, jq present)",
  "lease: acquired 35146676018-blue",
  "restore: pulled snapshots/20260917T031500Z into /root/work_data",
  "tunnel: cloudflared connector up for node.example.com",
  "workload: started runner/workload.sh (pid 4211)",
  "heartbeat: phase=serving slot=blue",
];

export const internals = {
  invoke: async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
    if (cmd === "logs_tail") {
      // A steady stream, wrapped rather than exhausted. A log view that stops
      // updating is the easy case; the interesting one is the view that re-renders
      // underneath the operator while they are typing in its search field.
      const since = Number(args?.["since"] ?? 0);
      const fresh = [0, 1].map((offset) => LOG_LINES[(since + offset) % LOG_LINES.length] ?? "");
      logSeq = since + fresh.length;
      return { next_seq: logSeq, lines: fresh } as T;
    }
    return invoke<T>(cmd, args);
  },
};
