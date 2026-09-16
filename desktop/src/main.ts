/**
 * Application wiring.
 *
 * Polling rather than pushed events, on purpose. The backend already polls
 * GitHub every 30 seconds; the frontend polls the *local* command layer every
 * two seconds, which involves no network and no cross-process event plumbing.
 * That keeps the renderer free of any API surface beyond a single `invoke`
 * function, which is a meaningful reduction in what a compromised renderer can
 * reach.
 *
 * The one thing polling must not do is fight the user: re-rendering the whole
 * dashboard is fine because it holds no text inputs, but Settings renders on
 * demand only, and the log view suspends auto-scroll while the user is reading
 * further up.
 */

import { api, describeError } from "./api";
import * as ui from "./ui";
import type { AppInfo, Config, DriveEntry, Heartbeat, KdfParams, NodeStatus, VaultStatus } from "./types";

const DASHBOARD_POLL_MS = 2000;
const SETTINGS_POLL_MS = 15000;
const LOG_POLL_MS = 1500;
const LEDGER_POLL_MS = 60000;

interface LogLine {
  seq: number;
  text: string;
}

type TabName = "dashboard" | "settings" | "logs";

interface AppStore {
  vault: VaultStatus | null;
  config: Config | null;
  status: NodeStatus | null;
  info: AppInfo | null;
  kdf: KdfParams | null;
  ledger: DriveEntry[];
  ledgerError: string | null;
  heartbeat: Heartbeat | null;
  logs: LogLine[];
  logSeq: number;
  logPaused: boolean;
  logSearch: string;
  tab: TabName;
  /**
   * Set to request a re-render of a panel that is not otherwise re-rendered on
   * every tick. The Settings panel is skipped by the poll loop so that typing in
   * a field is never interrupted, which means an explicit render has to be asked
   * for after any action that changes it.
   */
  forceRender: boolean;
  /** Populated by actions, shown as an inline report until dismissed. */
  report: ui.Alert[];
}

const store: AppStore = {
  vault: null,
  config: null,
  status: null,
  info: null,
  kdf: null,
  ledger: [],
  ledgerError: null,
  heartbeat: null,
  logs: [],
  logSeq: 0,
  logPaused: false,
  logSearch: "",
  tab: "dashboard",
  forceRender: false,
  report: [],
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function pushReport(kind: ui.Alert["kind"], text: string): void {
  store.report = [{ kind, text }];
  render();
}

/**
 * Copy text to the clipboard.
 *
 * `navigator.clipboard` needs a focused, secure context; the fallback exists
 * because the copy button is used for the one value an operator will paste most
 * often, and silently failing would be worse than the old API.
 */
async function copyToClipboard(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    pushReport("info", "Copied to the clipboard.");
    return;
  } catch {
    // fall through
  }
  const scratch = document.createElement("textarea");
  scratch.value = text;
  scratch.setAttribute("readonly", "");
  scratch.style.position = "fixed";
  scratch.style.opacity = "0";
  document.body.append(scratch);
  scratch.select();
  try {
    document.execCommand("copy");
    pushReport("info", "Copied to the clipboard.");
  } catch {
    pushReport("warn", "The clipboard is not available; select the text and copy it manually.");
  }
  scratch.remove();
}

function openExternal(url: string): void {
  // A run URL is the only external link the app ever wants to open, and it is
  // always a github.com URL the API returned. No generic navigation is exposed.
  window.open(url, "_blank", "noopener,noreferrer");
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderChips(): void {
  const vaultChip = document.getElementById("vault-chip");
  if (vaultChip) {
    vaultChip.textContent = ui.vaultChipText(store.vault);
    vaultChip.className = `chip ${ui.vaultChipClass(store.vault)}`;
  }
  const nodeChip = document.getElementById("node-chip");
  if (nodeChip) {
    nodeChip.textContent = ui.nodeChipText(store.status);
    nodeChip.className = `chip ${ui.phaseChipClass(store.status)}`;
  }
  const subtitle = document.getElementById("app-subtitle");
  if (subtitle) {
    const cycle = store.config?.cycle_minutes ?? 340;
    subtitle.textContent = store.config?.owner
      ? `${store.config.owner}/${store.config.repo} · ${cycle} min cycles · slot ${store.status?.slot ?? "?"}`
      : "no repository configured";
  }
}

function renderAlerts(): void {
  const region = document.getElementById("alert-region");
  if (!region) {
    return;
  }
  const alerts = [
    ...store.report,
    ...ui.deriveAlerts(store.vault, store.status, store.config),
  ];
  region.replaceChildren(...Array.from(ui.renderAlerts(alerts).children));
}

let settingsScroll = 0;

function render(): void {
  renderChips();
  renderAlerts();

  const dashboard = document.getElementById("panel-dashboard");
  if (dashboard && store.tab === "dashboard") {
    dashboard.replaceChildren(
      ui.renderDashboard(
        store.vault,
        store.status,
        store.config,
        store.ledger,
        store.heartbeat,
        store.ledgerError,
        {
          onForceMigration: handleForceMigration,
          onToggleKillSwitch: handleToggleKillSwitch,
          onCopyHostname: (hostname) => {
            void copyToClipboard(hostname.startsWith("http") ? hostname : `https://${hostname}`);
          },
          onRefreshLedger: () => {
            void refreshLedger(true);
          },
          onOpenRun: openExternal,
        },
      ),
    );
  }

  const settings = document.getElementById("panel-settings");
  if (settings && store.tab === "settings" && !store.forceRender) {
    settingsScroll = settings.scrollTop;
    settings.replaceChildren(
      ui.renderSettings(store.vault, store.config, store.info, store.kdf, {
        onInitVault: handleInitVault,
        onUnlock: handleUnlock,
        onUnlockOs: () => {
          void withReport(async () => {
            store.vault = await api.vaultUnlockOs();
            return "Vault unlocked with the Windows-protected key.";
          });
        },
        onLock: () => {
          void withReport(async () => {
            store.vault = await api.vaultLock();
            store.ledger = [];
            store.ledgerError = null;
            store.heartbeat = null;
            return "Vault locked; decrypted material has been zeroized.";
          });
        },
        onCalibrate: () => {
          void withReport(async () => {
            const params = await api.vaultCalibrate();
            store.kdf = params;
            store.forceRender = true;
            return `KDF calibrated to ${Math.round(params.m_cost_kib / 1024)} MiB of memory, ${params.t_cost} pass(es).`;
          });
        },
        onSetSecret: (name, value, note) => {
          void withReport(async () => {
            if (!value) {
              throw new Error("paste a value first");
            }
            store.vault = await api.vaultSetSecret(name, value, note || undefined);
            store.forceRender = true;
            return `${name} stored in the vault.`;
          });
        },
        onDeleteSecret: (name) => {
          void withReport(async () => {
            store.vault = await api.vaultDeleteSecret(name);
            store.forceRender = true;
            return `${name} removed from the vault.`;
          });
        },
        onRotate: (current, next) => {
          void withReport(async () => {
            store.vault = await api.vaultRotate(current, next);
            store.forceRender = true;
            return "Master passphrase rotated and re-sealed.";
          });
        },
        onClearAlerts: () => {
          void withReport(async () => {
            store.vault = await api.vaultClearAlerts();
            store.forceRender = true;
            return "Integrity alerts cleared.";
          });
        },
        onDestroy: (passphrase) => {
          void withReport(async () => {
            store.vault = await api.vaultDestroy(passphrase);
            store.forceRender = true;
            return "Vault destroyed. The ciphertext is now unrecoverable.";
          });
        },
        onInjectSecrets: () => {
          void withReport(async () => {
            const reports = await api.secretsInject();
            const rows = reports.map(
              (item) => `${item.ok ? "✓" : "✗"} ${item.name}: ${item.detail}`,
            );
            store.forceRender = true;
            return `Secret injection finished.\n${rows.join("\n")}`;
          });
        },
        onSaveConfig: (config) => {
          void withReport(async () => {
            store.config = await api.configSet(config);
            store.forceRender = false;
            return "Settings saved.";
          });
        },
      }),
    );
    settings.scrollTop = settingsScroll;
    store.forceRender = false;
  }

  const logs = document.getElementById("panel-logs");
  if (logs && store.tab === "logs") {
    const view = logs.querySelector("#log-view") as HTMLElement | null;
    const wasAtBottom = view
      ? view.scrollTop + view.clientHeight >= view.scrollHeight - 24
      : true;

    logs.replaceChildren(
      ui.renderLogs(store.logs, store.logPaused, store.logSearch, {
        onTogglePause: () => {
          store.logPaused = !store.logPaused;
          store.forceRender = true;
          render();
        },
        onClear: () => {
          void withReport(async () => {
            await api.logsClear();
            store.logs = [];
            store.forceRender = true;
            return "Local log cleared.";
          });
        },
        onSearch: (needle) => {
          store.logSearch = needle;
          store.forceRender = true;
          render();
        },
        onCopy: () => {
          void copyToClipboard(store.logs.map((line) => line.text).join("\n"));
        },
      }),
    );

    // Auto-scroll only when the user was already at the bottom; otherwise they
    // are reading, and jumping them to the end would be hostile.
    if (wasAtBottom) {
      const fresh = logs.querySelector("#log-view") as HTMLElement | null;
      if (fresh) {
        fresh.scrollTop = fresh.scrollHeight;
      }
    }
  }
}

/** Run an action, surface either its message or its error, then refresh. */
async function withReport(action: () => Promise<string>): Promise<void> {
  try {
    const message = await action();
    pushReport("info", message);
  } catch (error) {
    pushReport("danger", describeError(error));
  }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

function handleInitVault(passphrase: string): void {
  void withReport(async () => {
    store.vault = await api.vaultInit(passphrase);
    store.forceRender = true;
    return "Vault created and unlocked. Add your credentials next.";
  });
}

function handleUnlock(passphrase: string): void {
  void withReport(async () => {
    store.vault = await api.vaultUnlock(passphrase);
    store.forceRender = true;
    return "Vault unlocked.";
  });
}

function handleForceMigration(): void {
  void withReport(async () => {
    const report = await api.nodeDispatch();
    // Refresh the status immediately so the slot change is visible rather than
    // waiting for the next tick.
    store.status = await api.nodeStatus();
    return `Successor dispatched into slot ${report.target_slot}. ${report.detail}`;
  });
}

function handleToggleKillSwitch(): void {
  void withReport(async () => {
    const next = !(store.status?.kill_switch ?? false);
    const result = await api.nodeSetKillSwitch(
      next,
      next ? "engaged from the dashboard" : "released from the dashboard",
    );
    store.status = await api.nodeStatus();
    return result.detail;
  });
}

async function refreshLedger(manual: boolean): Promise<void> {
  if (!store.vault?.unlocked) {
    if (manual) {
      pushReport("warn", "Unlock the vault first: the Drive credential lives inside it.");
    }
    return;
  }
  try {
    store.ledger = await api.driveLedger();
    store.ledgerError = null;
  } catch (error) {
    store.ledgerError = describeError(error);
    if (manual) {
      pushReport("danger", store.ledgerError);
    }
  }
  try {
    store.heartbeat = await api.driveHeartbeat();
  } catch {
    // A missing heartbeat is normal before the first node starts.
    store.heartbeat = null;
  }
}

// ---------------------------------------------------------------------------
// Poll loops
// ---------------------------------------------------------------------------

function startLoops(): void {
  setInterval(() => {
    void (async () => {
      try {
        store.status = await api.nodeStatus();
      } catch (error) {
        store.status = null;
        store.report = [{ kind: "danger", text: describeError(error) }];
      }
      render();
    })();
  }, DASHBOARD_POLL_MS);

  // Vault and config change rarely; polling them slowly keeps the chips honest
  // (for example after an auto-lock) without churning the DOM.
  setInterval(() => {
    void (async () => {
      try {
        const vault = await api.vaultStatus();
        const changed =
          !store.vault ||
          store.vault.unlocked !== vault.unlocked ||
          store.vault.tamper_strikes !== vault.tamper_strikes ||
          store.vault.secrets.length !== vault.secrets.length;
        store.vault = vault;
        if (changed) {
          store.forceRender = true;
          render();
        }
      } catch {
        // Leave the last known vault state in place.
      }
    })();
  }, SETTINGS_POLL_MS);

  setInterval(() => {
    void (async () => {
      if (store.logPaused) {
        return;
      }
      try {
        const tail = await api.logsTail(store.logSeq);
        if (tail.lines.length > 0) {
          store.logSeq = tail.next_seq;
          tail.lines.forEach((text, index) => {
            store.logs.push({ seq: store.logSeq - tail.lines.length + index, text });
          });
          if (store.logs.length > 2000) {
            store.logs = store.logs.slice(-2000);
          }
          if (store.tab === "logs") {
            store.forceRender = true;
            render();
          }
        }
      } catch {
        // The log tail is diagnostic; a failure here must not disturb the UI.
      }
    })();
  }, LOG_POLL_MS);

  setInterval(() => {
    if (store.tab === "dashboard" && store.vault?.unlocked) {
      void refreshLedger(false).then(render);
    }
  }, LEDGER_POLL_MS);
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

function wireTabs(): void {
  const tabs = document.querySelectorAll<HTMLButtonElement>(".tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const name = tab.dataset.tab as TabName;
      store.tab = name;
      store.forceRender = true;
      tabs.forEach((other) => {
        other.setAttribute("aria-selected", String(other === tab));
      });
      document.getElementById("panel-dashboard")?.classList.toggle("hidden", name !== "dashboard");
      document.getElementById("panel-settings")?.classList.toggle("hidden", name !== "settings");
      document.getElementById("panel-logs")?.classList.toggle("hidden", name !== "logs");
      render();
    });
  });
}

async function bootstrap(): Promise<void> {
  wireTabs();

  try {
    store.config = await api.configGet();
  } catch {
    store.config = null;
  }
  try {
    store.info = await api.appInfo();
  } catch {
    store.info = null;
  }
  try {
    store.vault = await api.vaultStatus();
  } catch (error) {
    pushReport(
      "danger",
      `Could not read the vault: ${describeError(error)}. This interface must run inside the desktop app.`,
    );
  }

  render();
  startLoops();
  await refreshLedger(false);
  render();
}

void bootstrap();
