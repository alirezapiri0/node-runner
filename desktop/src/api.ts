/**
 * The bridge to the Rust command layer.
 *
 * This is a hand-rolled wrapper over `window.__TAURI_INTERNALS__.invoke` rather
 * than a dependency on `@tauri-apps/api`. The official package is itself a thin
 * wrapper over this exact function, so using it directly keeps the frontend
 * genuinely zero-dependency -- which matters here because the renderer is the
 * part of the app most likely to be compromised, and every package it pulls in
 * would be reachable from it.
 *
 * Argument naming: Tauri maps camelCase keys from JavaScript onto snake_case
 * Rust parameters, so `kdfTargetMs` fills `kdf_target_ms`. Optional arguments
 * are omitted from the payload rather than sent as `undefined`, because serde
 * would reject an explicit null for an `Option<u64>` only in some shapes and it
 * is simpler never to send them.
 */

import type {
  AppInfo,
  Config,
  DispatchReport,
  DriveEntry,
  Heartbeat,
  KdfParams,
  KillSwitchState,
  LogTail,
  NodeStatus,
  SecretReport,
  VaultStatus,
} from "./types";

type InvokeArgs = Record<string, unknown>;

interface TauriInternals {
  invoke<T>(cmd: string, args?: InvokeArgs): Promise<T>;
}

const internals = (window as unknown as { __TAURI_INTERNALS__?: TauriInternals })
  .__TAURI_INTERNALS__;

/** True when running inside the desktop shell (as opposed to a plain browser). */
export const isDesktop = internals !== undefined;

async function invoke<T>(cmd: string, args?: InvokeArgs): Promise<T> {
  if (!internals) {
    throw new Error(
      "This interface only works inside the Node Runner desktop app; it cannot talk to the backend from a browser.",
    );
  }
  return internals.invoke<T>(cmd, args);
}

/** Drop keys whose value is `undefined` so they are not sent at all. */
function args(input: Record<string, unknown | undefined>): InvokeArgs {
  const out: InvokeArgs = {};
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined) {
      out[key] = value;
    }
  }
  return out;
}

export const api = {
  // -- vault ---------------------------------------------------------------
  vaultStatus: () => invoke<VaultStatus>("vault_status"),
  vaultCalibrate: () => invoke<KdfParams>("vault_calibrate"),
  vaultInit: (passphrase: string, kdfTargetMs?: number) =>
    invoke<VaultStatus>("vault_init", args({ passphrase, kdfTargetMs })),
  vaultUnlock: (passphrase: string) => invoke<VaultStatus>("vault_unlock", { passphrase }),
  vaultUnlockOs: () => invoke<VaultStatus>("vault_unlock_os"),
  vaultLock: () => invoke<VaultStatus>("vault_lock"),
  vaultSetSecret: (name: string, value: string, note?: string) =>
    invoke<VaultStatus>("vault_set_secret", args({ name, value, note })),
  vaultDeleteSecret: (name: string) => invoke<VaultStatus>("vault_delete_secret", { name }),
  vaultRotate: (currentPassphrase: string, newPassphrase: string, kdfTargetMs?: number) =>
    invoke<VaultStatus>(
      "vault_rotate",
      args({ currentPassphrase, newPassphrase, kdfTargetMs }),
    ),
  vaultClearAlerts: () => invoke<VaultStatus>("vault_clear_alerts"),
  vaultDestroy: (passphrase: string) => invoke<VaultStatus>("vault_destroy", { passphrase }),

  // -- configuration -------------------------------------------------------
  configGet: () => invoke<Config>("config_get"),
  configSet: (config: Config) => invoke<Config>("config_set", { config }),

  // -- node ----------------------------------------------------------------
  nodeStatus: () => invoke<NodeStatus>("node_status"),
  nodeSetKillSwitch: (engaged: boolean, note?: string) =>
    invoke<KillSwitchState>("node_set_kill_switch", args({ engaged, note })),
  nodeDispatch: () => invoke<DispatchReport>("node_dispatch"),
  secretsInject: () => invoke<SecretReport[]>("secrets_inject"),

  // -- drive ---------------------------------------------------------------
  driveLedger: () => invoke<DriveEntry[]>("drive_ledger"),
  driveHeartbeat: () => invoke<Heartbeat | null>("drive_heartbeat"),

  // -- logs ----------------------------------------------------------------
  logsTail: (since: number) => invoke<LogTail>("logs_tail", { since }),
  logsClear: () => invoke<void>("logs_clear"),

  // -- diagnostics ---------------------------------------------------------
  appInfo: () => invoke<AppInfo>("app_info"),
};

/**
 * Turn a command rejection into something displayable.
 *
 * Rust command errors arrive as strings already sanitized of secret material
 * (the vault's error types never carry values), so this only has to cope with
 * the shell's own error shapes.
 */
export function describeError(error: unknown): string {
  if (typeof error === "string") {
    return error;
  }
  if (error instanceof Error) {
    return error.message;
  }
  try {
    return JSON.stringify(error);
  } catch {
    return "an unknown error occurred";
  }
}
