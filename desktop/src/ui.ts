/**
 * Rendering.
 *
 * Two rules shape this module:
 *
 * 1. **The dashboard is re-rendered wholesale on every poll; the Settings panel
 *    is not.** The dashboard contains no text inputs, so replacing it cannot
 *    disturb anyone, while Settings is full of fields and re-rendering it would
 *    steal focus mid-keystroke. Settings renders on demand and its values are
 *    read back out of the DOM when saving.
 * 2. **No secret value ever enters the DOM.** The credentials list shows names,
 *    timestamps and notes. Pasting a credential writes straight to the backend
 *    through `invoke` and the field is cleared immediately afterwards.
 */

import * as cd from "./countdown";
import type {
  AppInfo,
  Config,
  DriveEntry,
  Heartbeat,
  KdfParams,
  NodeStatus,
  SecretView,
  VaultStatus,
} from "./types";
import { REQUIRED_SECRETS } from "./types";

type Child = Node | string | null | undefined | false;
type Props = Record<string, unknown>;

function applyProps(node: Element, props: Props): void {
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) {
      continue;
    }
    if (key === "class") {
      node.setAttribute("class", String(value));
    } else if (key === "text") {
      node.textContent = String(value);
    } else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else {
      node.setAttribute(key, String(value));
    }
  }
}

function appendChildren(node: Element, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) {
      continue;
    }
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
}

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  applyProps(node, props);
  appendChildren(node, children);
  return node;
}

/**
 * SVG elements need their own namespace, and `document.createElement` will not
 * produce a renderable `<circle>`. Kept separate from `h` rather than guessed at
 * with a cast, because a silently non-rendering countdown ring is exactly the
 * kind of bug nobody notices until a migration.
 */
export function svg<K extends keyof SVGElementTagNameMap>(
  tag: K,
  props: Props = {},
  ...children: Child[]
): SVGElementTagNameMap[K] {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  applyProps(node, props);
  appendChildren(node, children);
  return node;
}

export function clear(node: HTMLElement): void {
  node.replaceChildren();
}

export function row(label: string, value: Child, valueClass = ""): HTMLElement {
  return h(
    "div",
    { class: "row" },
    h("span", { class: "row-label", text: label }),
    typeof value === "string"
      ? h("span", { class: `row-value ${valueClass}`, text: value })
      : h("span", { class: `row-value ${valueClass}` }, value),
  );
}

export interface Alert {
  kind: "info" | "warn" | "danger";
  text: string;
  dismissible?: boolean;
}

export interface DashboardActions {
  onForceMigration: () => void;
  onToggleKillSwitch: () => void;
  onCopyHostname: (hostname: string) => void;
  onRefreshLedger: () => void;
  onOpenRun: (url: string) => void;
}

export interface SettingsActions {
  onInitVault: (passphrase: string) => void;
  onUnlock: (passphrase: string) => void;
  onUnlockOs: () => void;
  onLock: () => void;
  onCalibrate: () => void;
  onSetSecret: (name: string, value: string, note: string) => void;
  onDeleteSecret: (name: string) => void;
  onRotate: (current: string, next: string) => void;
  onClearAlerts: () => void;
  onDestroy: (passphrase: string) => void;
  onInjectSecrets: () => void;
  onSaveConfig: (config: Config) => void;
}

export interface LogsActions {
  onTogglePause: () => void;
  onClear: () => void;
  onSearch: (needle: string) => void;
  onCopy: () => void;
}

/** Human-readable label for a GitHub run status or local phase. */
function phaseLabel(status: NodeStatus | null): string {
  if (!status) return "unknown";
  switch (status.phase) {
    case "locked":
      return "vault locked";
    case "unconfigured":
      return "not configured";
    case "no_credential":
      return "credential missing";
    case "no_runs":
      return "no runs yet";
    case "in_progress":
      return "running";
    case "queued":
    case "requested":
    case "waiting":
    case "pending":
      return "starting";
    case "completed":
      return status.conclusion ? `finished: ${status.conclusion}` : "finished";
    default:
      return status.phase;
  }
}

export function phaseChipClass(status: NodeStatus | null): string {
  if (!status) return "chip-muted";
  switch (status.phase) {
    case "in_progress":
      return "chip-ok";
    case "queued":
    case "requested":
    case "waiting":
    case "pending":
      return "chip-busy";
    case "completed":
      return status.conclusion === "success" ? "chip-muted" : "chip-danger";
    case "locked":
    case "unconfigured":
    case "no_credential":
      return "chip-warn";
    default:
      return "chip-muted";
  }
}

export function nodeChipText(status: NodeStatus | null): string {
  if (!status) return "node unknown";
  const slot = status.slot && status.slot !== "?" ? ` · slot ${status.slot}` : "";
  return `node ${phaseLabel(status)}${slot}`;
}

export function vaultChipText(vault: VaultStatus | null): string {
  if (!vault) return "vault unknown";
  if (!vault.exists) return "vault not created";
  return vault.unlocked ? "vault unlocked" : "vault locked";
}

export function vaultChipClass(vault: VaultStatus | null): string {
  if (!vault) return "chip-muted";
  if (!vault.exists) return "chip-warn";
  return vault.unlocked ? "chip-ok" : "chip-muted";
}

/** Turn vault and config state into the alerts banner. */
export function deriveAlerts(vault: VaultStatus | null, status: NodeStatus | null, config: Config | null): Alert[] {
  const alerts: Alert[] = [];

  if (vault && vault.tamper_strikes > 0) {
    const last = vault.tamper_log[0];
    alerts.push({
      kind: "danger",
      text:
        `Vault integrity alert: ${vault.tamper_strikes} recorded event(s).` +
        (last ? ` Most recent: ${last.detail} (${cd.relativeTime(last.at_unix)}).` : "") +
        " Investigate before entering credentials again.",
    });
  }
  if (vault && vault.recoverable_from_backup) {
    alerts.push({
      kind: "danger",
      text: "The vault file is missing but a previous generation exists; the next successful open restores from it.",
    });
  }
  if (vault && vault.protector === "ProtectionChanged") {
    alerts.push({
      kind: "warn",
      text: "The OS protector reports the vault's protection is no longer intact. This usually means the Windows profile was migrated or restored. The passphrase will still open it.",
    });
  }
  if (vault && vault.exists && !vault.os_wrap) {
    alerts.push({
      kind: "warn",
      text: "This vault has no OS-protected key, so changing or saving credentials requires the passphrase each time.",
    });
  }
  if (vault && vault.unlocked && !vault.swap_protection) {
    alerts.push({
      kind: "warn",
      text: "This platform cannot pin secret pages against swap; decrypted values could in principle reach the page file.",
    });
  }
  if (status?.kill_switch) {
    alerts.push({
      kind: "warn",
      text: "The stop switch is engaged: the successor dispatch is suppressed and the running node will not hand over until it is released.",
    });
  }
  if (status?.error) {
    alerts.push({ kind: "danger", text: `GitHub polling failed: ${status.error}` });
  }
  if (config && !config.owner) {
    alerts.push({
      kind: "info",
      text: "Set the repository owner and name in Settings to start observing a node.",
    });
  }
  return alerts;
}

export function renderAlerts(alerts: Alert[]): HTMLElement {
  const region = h("div", { class: "alert-region" });
  for (const alert of alerts) {
    region.append(
      h("div", { class: `alert alert-${alert.kind}` }, h("span", { text: alert.text })),
    );
  }
  return region;
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export function renderDashboard(
  vault: VaultStatus | null,
  status: NodeStatus | null,
  config: Config | null,
  ledger: DriveEntry[],
  heartbeat: Heartbeat | null,
  ledgerError: string | null,
  actions: DashboardActions,
): HTMLElement {
  const panel = h("div", { class: "grid" });
  const cycleSeconds = (config?.cycle_minutes ?? 340) * 60;
  const remaining = status?.remaining_secs ?? null;
  const hostname = config?.tunnel_hostname ?? "";

  // -- countdown -----------------------------------------------------------
  const progress = svg("circle", {
    class: `ring-progress ${cd.urgencyClass(remaining, cycleSeconds)}`,
    cx: 66,
    cy: 66,
    r: cd.RING.radius,
    "stroke-dasharray": cd.RING.circumference.toFixed(2),
    "stroke-dashoffset": cd.ringDashOffset(remaining, cycleSeconds).toFixed(2),
  });

  const countdownCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "Instance lifetime" }),
    h("p", { class: "card-note", text: "Derived from GitHub's own start timestamp, so it survives restarts and sleep." }),
    h(
      "div",
      { class: "countdown" },
      h(
        "div",
        { class: "ring-wrap" },
        svg(
          "svg",
          { class: "ring", width: 132, height: 132, viewBox: "0 0 132 132" },
          svg("circle", { class: "ring-track", cx: 66, cy: 66, r: cd.RING.radius }),
          progress,
        ),
        h(
          "div",
          { class: "ring-label" },
          h("span", { class: "ring-time", text: cd.formatDuration(remaining) }),
          h("span", { class: "ring-caption", text: "remaining" }),
        ),
      ),
      h(
        "div",
        { class: "countdown-meta" },
        h("span", { class: "slot-badge", text: `slot ${status?.slot ?? "?"}` }),
        h("span", {
          class: "mono-inline dim-text",
          text:
            status?.elapsed_secs !== null && status?.elapsed_secs !== undefined
              ? `up ${cd.formatDuration(status.elapsed_secs)} of ${cd.formatDuration(cycleSeconds)}`
              : "no active run observed",
        }),
        h(
          "div",
          { class: "button-row" },
          h("button", {
            class: "action primary",
            type: "button",
            text: "Force migration / failover",
            disabled: !vault?.unlocked || !config?.owner || status?.kill_switch,
            onclick: actions.onForceMigration,
          }),
          status?.run_url
            ? h("button", {
                class: "action ghost",
                type: "button",
                text: "Open run",
                onclick: () => actions.onOpenRun(status.run_url as string),
              })
            : null,
        ),
      ),
    ),
  );

  // -- tunnel --------------------------------------------------------------
  const tunnelCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "Static endpoint" }),
    h("p", { class: "card-note", text: "A named Cloudflare tunnel, so this hostname is identical on every node." }),
    h(
      "div",
      { class: "row" },
      h("span", { class: "row-value", text: hostname || "not configured" }),
      h("button", {
        class: "action",
        type: "button",
        text: "Copy",
        disabled: !hostname,
        onclick: () => actions.onCopyHostname(hostname),
      }),
    ),
    row(
      "Tunnel health",
      heartbeat ? `${heartbeat.phase || "unknown"}` : "no heartbeat yet",
      heartbeat ? "value-ok" : "value-dim",
    ),
    row(
      "Last heartbeat",
      heartbeat ? cd.relativeTime(heartbeat.heartbeat_unix) : "never",
      heartbeat ? "" : "value-dim",
    ),
    row("Serving run", heartbeat?.run_id ? String(heartbeat.run_id) : "—"),
    row("Node slot", heartbeat?.slot || status?.slot || "—"),
  );

  // -- node --------------------------------------------------------------
  const killSwitch = status?.kill_switch ?? false;
  const nodeCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "Node" }),
    h("p", { class: "card-note", text: "Polled every 30 seconds with conditional requests." }),
    row("Phase", phaseLabel(status)),
    row("Run id", status?.run_id ? String(status.run_id) : "—"),
    row(
      "Repository",
      config && config.owner && config.repo ? `${config.owner}/${config.repo}` : "not configured",
    ),
    row("Last poll", cd.relativeTime(status?.last_poll_unix ?? null)),
    row(
      "API budget left",
      status?.rate_limit_remaining !== null && status?.rate_limit_remaining !== undefined
        ? String(status.rate_limit_remaining)
        : "—",
    ),
    h(
      "div",
      { class: "button-row" },
      h("button", {
        class: killSwitch ? "action primary" : "action danger",
        type: "button",
        text: killSwitch ? "Release stop switch" : "Engage stop switch",
        disabled: !vault?.unlocked,
        onclick: actions.onToggleKillSwitch,
      }),
    ),
    h("p", {
      class: "card-note",
      text: "The stop switch writes a marker to Drive that the running node checks before it freezes and hands over, and suppresses dispatch from this app.",
    }),
  );

  // -- backup ledger -------------------------------------------------------
  const ledgerRows: HTMLElement[] = [];
  if (ledgerError) {
    ledgerRows.push(h("p", { class: "empty-state", text: `Ledger unavailable: ${ledgerError}` }));
  } else if (ledger.length === 0) {
    ledgerRows.push(h("p", { class: "empty-state", text: "No snapshots recorded yet." }));
  } else {
    const table = h(
      "table",
      { class: "table-ledger" },
      h(
        "thead",
        {},
        h("tr", {}, h("th", { text: "Snapshot" }), h("th", { text: "Taken" }), h("th", { text: "Size" })),
      ),
    );
    const body = h("tbody", {});
    for (const entry of ledger.slice(0, 20)) {
      body.append(
        h(
          "tr",
          {},
          h("td", { text: entry.name }),
          h("td", { text: cd.relativeTime(entry.modified_unix) }),
          h("td", { class: "cell-size", text: cd.formatBytes(entry.size) }),
        ),
      );
    }
    table.append(body);
    ledgerRows.push(table);
  }

  const ledgerCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "Backup ledger" }),
    h("p", {
      class: "card-note",
      text: `Snapshots on Drive, newest first. Retention is configured as ${config?.backup_retention ?? 20}.`,
    }),
    ...ledgerRows,
    h(
      "div",
      { class: "button-row" },
      h("button", {
        class: "action",
        type: "button",
        text: "Refresh ledger",
        disabled: !vault?.unlocked,
        onclick: actions.onRefreshLedger,
      }),
    ),
  );

  // -- runner log tail -----------------------------------------------------
  const tailCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "Runner log tail" }),
    h("p", {
      class: "card-note",
      text: "Relayed from the node's heartbeat. GitHub only serves run logs after a run completes, so a live stream is not available from the API.",
    }),
  );
  if (heartbeat && heartbeat.log_tail.length > 0) {
    tailCard.append(
      h(
        "div",
        { class: "heartbeat-tail" },
        h("pre", { text: heartbeat.log_tail.slice(-14).join("\n") }),
      ),
    );
  } else {
    tailCard.append(h("p", { class: "empty-state", text: "No output relayed yet." }));
  }

  panel.append(countdownCard, tunnelCard, nodeCard, ledgerCard, tailCard);
  return panel;
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

export function renderSettings(
  vault: VaultStatus | null,
  config: Config | null,
  info: AppInfo | null,
  kdf: KdfParams | null,
  actions: SettingsActions,
): HTMLElement {
  const wrap = h("div", { class: "grid" });
  const cfg: Config = config ?? {
    owner: "",
    repo: "",
    workflow_file: "runner.yml",
    cycle_minutes: 340,
    poll_seconds: 30,
    auto_lock_minutes: 15,
    workload_pattern: "",
    tunnel_hostname: "",
    drive_folder_id: "",
    backup_retention: 20,
  };
  const unlocked = vault?.unlocked ?? false;

  // -- vault ---------------------------------------------------------------
  const vaultCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "Vault" }),
    h("p", {
      class: "card-note",
      text: "Credentials are sealed with Argon2id and AES-256-GCM, with the master key also wrapped by Windows DPAPI.",
    }),
  );

  vaultCard.append(
    row("Status", vault?.exists ? (unlocked ? "unlocked" : "locked") : "not created", unlocked ? "value-ok" : ""),
    row("Envelope", vault?.format ?? "—"),
    row(
      "KDF",
      vault?.kdf
        ? `Argon2id ${Math.round(vault.kdf.m_cost_kib / 1024)} MiB, t=${vault.kdf.t_cost}, p=${vault.kdf.p_cost}`
        : kdf
          ? `calibrated: ${Math.round(kdf.m_cost_kib / 1024)} MiB, t=${kdf.t_cost}`
          : "—",
    ),
    row(
      "OS protection",
      vault?.binding_label ?? "not present",
      vault?.os_wrap ? "value-ok" : "value-warn",
    ),
    row(
      "Swap protection",
      vault?.swap_protection ? "pages pinned" : "unavailable on this platform",
      vault?.swap_protection ? "value-ok" : "value-warn",
    ),
    row(
      "Protector health",
      vault?.protector ?? "—",
      vault?.protector === "Healthy" ? "value-ok" : "value-warn",
    ),
    row("Rotations", vault?.rotate_count ? String(vault.rotate_count) : "0"),
  );

  vaultCard.append(
    h("p", {
      class: "footer-note",
      id: "dpapi-caption",
      text:
        "Windows DPAPI binds the key to your user profile, which protects against offline disk theft and other accounts on this machine. It is not TPM-bound, and it does not protect against malware already running as you.",
    }),
  );

  if (vault?.exists) {
    if (!unlocked) {
      const unlockField = h("input", {
        type: "password",
        id: "unlock-passphrase",
        autocomplete: "current-password",
        placeholder: "master passphrase",
      });
      vaultCard.append(
        h("div", { class: "divider" }),
        h("label", { class: "field" }, h("span", { class: "field-label", text: "Unlock" }), unlockField),
        h(
          "div",
          { class: "button-row" },
          h("button", {
            class: "action primary",
            type: "button",
            text: "Unlock",
            onclick: () => {
              actions.onUnlock((unlockField as HTMLInputElement).value);
              (unlockField as HTMLInputElement).value = "";
            },
          }),
          h("button", {
            class: "action",
            type: "button",
            text: "Unlock with Windows",
            disabled: !vault.os_wrap,
            onclick: actions.onUnlockOs,
          }),
        ),
      );
    } else {
      vaultCard.append(
        h("div", { class: "divider" }),
        h(
          "div",
          { class: "button-row" },
          h("button", { class: "action", type: "button", text: "Lock now", onclick: actions.onLock }),
          h("button", { class: "action", type: "button", text: "Re-calibrate KDF", onclick: actions.onCalibrate }),
          vault?.tamper_strikes
            ? h("button", {
                class: "action",
                type: "button",
                text: "Clear integrity alerts",
                onclick: actions.onClearAlerts,
              })
            : null,
        ),
      );
    }
  } else {
    const newPass = h("input", {
      type: "password",
      id: "init-passphrase",
      autocomplete: "new-password",
      placeholder: "at least 12 characters, mixed classes",
    });
    vaultCard.append(
      h("div", { class: "divider" }),
      h("label", { class: "field" }, h("span", { class: "field-label", text: "Create vault" }), newPass),
      h(
        "div",
        { class: "button-row" },
        h("button", {
          class: "action primary",
          type: "button",
          text: "Create vault",
          onclick: () => {
            actions.onInitVault((newPass as HTMLInputElement).value);
            (newPass as HTMLInputElement).value = "";
          },
        }),
        h("button", { class: "action", type: "button", text: "Measure KDF cost", onclick: actions.onCalibrate }),
      ),
    );
  }

  // -- credentials ---------------------------------------------------------
  const credCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "Credentials" }),
    h("p", {
      class: "card-note",
      text: "Stored values can never be read back — not by this interface, and not by any command it can call. Only the name, timing and note are shown.",
    }),
  );

  if (vault && vault.secrets.length > 0) {
    const table = h(
      "table",
      { class: "table-secrets" },
      h(
        "thead",
        {},
        h("tr", {}, h("th", { text: "Name" }), h("th", { text: "Updated" }), h("th", { text: "Note" }), h("th", { text: "" })),
      ),
    );
    const body = h("tbody", {});
    for (const secret of vault.secrets as SecretView[]) {
      body.append(
        h(
          "tr",
          {},
          h("td", { class: "secret-name", text: secret.name }),
          h("td", { text: cd.relativeTime(secret.rotated_at_unix ?? secret.created_at_unix) }),
          h("td", { text: secret.note ?? "—" }),
          h(
            "td",
            { class: "cell-actions" },
            h("button", {
              class: "action ghost",
              type: "button",
              text: "Delete",
              disabled: !unlocked,
              onclick: () => actions.onDeleteSecret(secret.name),
            }),
          ),
        ),
      );
    }
    table.append(body);
    credCard.append(table);
  } else {
    credCard.append(h("p", { class: "empty-state", text: "No credentials stored yet." }));
  }

  // One entry row per expected secret, so the required set is discoverable
  // rather than something the operator has to remember.
  credCard.append(h("div", { class: "divider" }));
  for (const requirement of REQUIRED_SECRETS) {
    const valueInput = requirement.multiline
      ? h("textarea", { id: `secret-value-${requirement.name}`, placeholder: "paste the JSON key file contents" })
      : h("input", { type: "password", id: `secret-value-${requirement.name}`, placeholder: "paste the value" });

    credCard.append(
      h(
        "div",
        {},
        h("label", { class: "field" },
          h("span", { class: "field-label" },
            h("span", { class: "secret-name", text: requirement.name }),
          ),
          valueInput,
          h("span", { class: "field-hint", text: requirement.purpose }),
        ),
      ),
    );

    const buttons: HTMLElement[] = [
      h("button", {
        class: "action",
        type: "button",
        text: "Save to vault",
        disabled: !unlocked,
        onclick: () => {
          const field = document.getElementById(`secret-value-${requirement.name}`) as
            | HTMLInputElement
            | HTMLTextAreaElement
            | null;
          const value = field?.value ?? "";
          actions.onSetSecret(requirement.name, value, "");
          if (field) field.value = "";
        },
      }),
    ];

    if (requirement.multiline) {
      // A file picker for the service-account JSON: it is read in the renderer
      // and handed straight to the vault, then the field is cleared. Nothing is
      // written to disk by the UI.
      const fileInput = h("input", {
        type: "file",
        accept: ".json,application/json",
        class: "hidden",
        id: `secret-file-${requirement.name}`,
      }) as HTMLInputElement;
      fileInput.addEventListener("change", async () => {
        const file = fileInput.files?.[0];
        if (!file) return;
        const text = await file.text();
        const field = document.getElementById(`secret-value-${requirement.name}`) as
          | HTMLTextAreaElement
          | null;
        if (field) {
          field.value = text;
        }
        fileInput.value = "";
      });
      buttons.push(
        h("button", {
          class: "action",
          type: "button",
          text: "Choose file…",
          onclick: () => fileInput.click(),
        }),
      );
      buttons.push(fileInput);
    }

    credCard.append(h("div", { class: "button-row" }, ...buttons));
  }

  if (vault?.exists) {
    const rotateField = h("input", {
      type: "password",
      id: "rotate-current",
      placeholder: "current passphrase",
    });
    const newField = h("input", { type: "password", id: "rotate-new", placeholder: "new passphrase" });
    credCard.append(
      h("div", { class: "divider" }),
      h("h3", { text: "Rotate the master passphrase" }),
      h("p", {
        class: "card-note",
        text: "Requires the current passphrase, not merely an unlocked session, so a stolen unlocked laptop cannot lock you out.",
      }),
      h("label", { class: "field" }, h("span", { class: "field-label", text: "Current" }), rotateField),
      h("label", { class: "field" }, h("span", { class: "field-label", text: "New" }), newField),
      h(
        "div",
        { class: "button-row" },
        h("button", {
          class: "action",
          type: "button",
          text: "Rotate",
          onclick: () => {
            actions.onRotate(
              (rotateField as HTMLInputElement).value,
              (newField as HTMLInputElement).value,
            );
            (rotateField as HTMLInputElement).value = "";
            (newField as HTMLInputElement).value = "";
          },
        }),
      ),
      h("div", { class: "divider" }),
      h("h3", { class: "danger-text", text: "Destroy the vault" }),
      h("p", {
        class: "card-note",
        text: "Crypto-erase: deleting the wrapped key makes the ciphertext unrecoverable. Requires the passphrase.",
      }),
      (() => {
        const destroyField = h("input", {
          type: "password",
          id: "destroy-passphrase",
          placeholder: "passphrase, to confirm",
        });
        return h("div", {},
          destroyField,
          h("div", { class: "button-row" },
            h("button", {
              class: "action danger",
              type: "button",
              text: "Destroy vault",
              onclick: () => {
                actions.onDestroy((destroyField as HTMLInputElement).value);
                (destroyField as HTMLInputElement).value = "";
              },
            }),
          ),
        );
      })(),
    );
  }

  // -- repository and cycle ------------------------------------------------
  const field = (id: string, label: string, value: string | number, hint?: string, type = "text") =>
    h(
      "label",
      { class: "field" },
      h("span", { class: "field-label", text: label }),
      h("input", { type, id, value: String(value) }),
      hint ? h("span", { class: "field-hint", text: hint }) : null,
    );

  const repoCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "Repository and cycle" }),
    h("p", {
      class: "card-note",
      text: "All nodes share one repository. The predecessor dispatches the successor into the idle slot, so no new repository is ever created.",
    }),
    h(
      "div",
      { class: "field-grid" },
      field("cfg-owner", "Owner", cfg.owner),
      field("cfg-repo", "Repository", cfg.repo),
      field("cfg-workflow", "Workflow file", cfg.workflow_file, "path under .github/workflows"),
      field("cfg-cycle", "Cycle length (minutes)", cfg.cycle_minutes, "must stay at or below 340", "number"),
      field("cfg-poll", "Poll interval (seconds)", cfg.poll_seconds, "10 or more", "number"),
      field("cfg-lock", "Auto-lock after (minutes)", cfg.auto_lock_minutes, "cannot be disabled", "number"),
      field("cfg-workload", "Workload match pattern", cfg.workload_pattern, "passed to pkill -STOP before snapshotting"),
      field("cfg-tunnel", "Tunnel hostname", cfg.tunnel_hostname, "the static Cloudflare endpoint"),
      field("cfg-folder", "Drive folder id", cfg.drive_folder_id, "shared with the service account"),
      field("cfg-retention", "Backup retention", cfg.backup_retention, "rolling window of snapshots", "number"),
    ),
    h(
      "div",
      { class: "button-row" },
      h("button", {
        class: "action primary",
        type: "button",
        text: "Save settings",
        onclick: () => {
          const read = (id: string) => (document.getElementById(id) as HTMLInputElement | null)?.value ?? "";
          const readNumber = (id: string, fallback: number) => {
            const parsed = Number.parseInt(read(id), 10);
            return Number.isFinite(parsed) ? parsed : fallback;
          };
          actions.onSaveConfig({
            owner: read("cfg-owner").trim(),
            repo: read("cfg-repo").trim(),
            workflow_file: read("cfg-workflow").trim() || "runner.yml",
            cycle_minutes: readNumber("cfg-cycle", 340),
            poll_seconds: readNumber("cfg-poll", 30),
            auto_lock_minutes: readNumber("cfg-lock", 15),
            workload_pattern: read("cfg-workload").trim(),
            tunnel_hostname: read("cfg-tunnel").trim(),
            drive_folder_id: read("cfg-folder").trim(),
            backup_retention: readNumber("cfg-retention", 20),
          });
        },
      }),
      h("button", {
        class: "action",
        type: "button",
        text: "Inject credentials into the repository",
        disabled: !unlocked,
        onclick: actions.onInjectSecrets,
      }),
    ),
    h("p", {
      class: "footer-note",
      text: "Injection seals each credential to the repository's public key (libsodium sealed boxes) and uploads it. GitHub secrets are write-only: the write being accepted is the only confirmation available, and the vault remains the sole readable copy.",
    }),
  );

  // -- diagnostics ---------------------------------------------------------
  const infoCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "Diagnostics" }),
    row("Application version", info?.version ?? "—"),
    row("Data directory", info?.data_dir ?? "—"),
    row("Vault file", info?.vault_path ?? "—"),
    row("OS key protection", info?.os_protection ? "available" : "unavailable", info?.os_protection ? "value-ok" : "value-warn"),
    row("Swap protection", info?.swap_protection ? "available" : "unavailable", info?.swap_protection ? "value-ok" : "value-warn"),
    row("Protector probe", info?.protector_status ?? "—"),
  );

  wrap.append(vaultCard, credCard, repoCard, infoCard);
  return wrap;
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

export function renderLogs(
  lines: { seq: number; text: string }[],
  paused: boolean,
  needle: string,
  actions: LogsActions,
): HTMLElement {
  const searchInput = h("input", {
    type: "text",
    id: "log-search",
    placeholder: "filter",
    value: needle,
  }) as HTMLInputElement;
  searchInput.addEventListener("input", () => actions.onSearch(searchInput.value));

  const toolbar = h(
    "div",
    { class: "logs-toolbar" },
    h("button", {
      class: paused ? "action primary" : "action",
      type: "button",
      text: paused ? "Resume" : "Pause",
      onclick: actions.onTogglePause,
    }),
    searchInput,
    h("button", { class: "action", type: "button", text: "Copy", onclick: actions.onCopy }),
    h("button", { class: "action ghost", type: "button", text: "Clear", onclick: actions.onClear }),
  );

  const view = h("div", { class: "log-view", id: "log-view" });
  const lowered = needle.trim().toLowerCase();

  for (const line of lines) {
    const isError = /error|failed|panic|refus/i.test(line.text);
    const isWarn = /warn|retry|slow/i.test(line.text);
    const element = h("div", {
      class: `log-line${isError ? " is-error" : isWarn ? " is-warn" : ""}`,
    });
    if (lowered && line.text.toLowerCase().includes(lowered)) {
      const at = line.text.toLowerCase().indexOf(lowered);
      element.append(
        document.createTextNode(line.text.slice(0, at)),
        h("mark", { text: line.text.slice(at, at + lowered.length) }),
        document.createTextNode(line.text.slice(at + lowered.length)),
      );
    } else {
      element.textContent = line.text;
    }
    view.append(element);
  }

  if (lines.length === 0) {
    view.append(h("p", { class: "empty-state", text: "No log output yet." }));
  }

  return h(
    "div",
    {},
    toolbar,
    h("p", {
      class: "card-note",
      text: "Local application log: vault events, polling failures and handover actions. The node's own output appears on the dashboard once it relays a heartbeat.",
    }),
    view,
  );
}
