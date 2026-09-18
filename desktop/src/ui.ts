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
    h("h2", { text: "چرخه مهاجرت نود (Migration Countdown)" }),
    h("p", { class: "card-note", text: "محاسبه زمان بر اساس تایم‌استمپ گیت‌هاب؛ زمان باقی‌مانده از چرخه ۶ ساعته جاب فعلی تا انتقال به جاب جدید." }),
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
          h("span", { class: "ring-caption", text: "باقی‌مانده (remaining)" }),
        ),
      ),
      h(
        "div",
        { class: "countdown-meta" },
        h("span", { class: "slot-badge", text: `اسلات ${status?.slot ?? "?"}` }),
        h("span", {
          class: "mono-inline dim-text",
          text:
            status?.elapsed_secs !== null && status?.elapsed_secs !== undefined
              ? `فعال: ${cd.formatDuration(status.elapsed_secs)} از ${cd.formatDuration(cycleSeconds)}`
              : "جاب فعالی در حال حاضر شناسایی نشد",
        }),
        h(
          "div",
          { class: "button-row" },
          h("button", {
            class: "action primary",
            type: "button",
            text: "انتقال دستی / جاب جدید (Force migration)",
            disabled: !vault?.unlocked || !config?.owner || status?.kill_switch,
            onclick: actions.onForceMigration,
          }),
          status?.run_url
            ? h("button", {
                class: "action ghost",
                type: "button",
                text: "مشاهده در گیت‌هاب (Open run)",
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
    h("h2", { text: "دامنه و تانل پایدار (Static Endpoint)" }),
    h("p", { class: "card-note", text: "تانل اختصاصی Cloudflare؛ این دامنه روی تمامی جاب‌های بعدی یکسان و پایدار باقی می‌ماند." }),
    h(
      "div",
      { class: "row" },
      h("span", { class: "row-value", text: hostname || "تنظیم نشده (not configured)" }),
      h("button", {
        class: "action",
        type: "button",
        text: "کپی دامنه (Copy)",
        disabled: !hostname,
        onclick: () => actions.onCopyHostname(hostname),
      }),
    ),
    row(
      "سلامت تانل (Tunnel health)",
      heartbeat ? `${heartbeat.phase || "unknown"}` : "هنوز ضربان سلامتی دریافت نشده",
      heartbeat ? "value-ok" : "value-dim",
    ),
    row(
      "آخرین ضربان سلامت (Last heartbeat)",
      heartbeat ? cd.relativeTime(heartbeat.heartbeat_unix) : "هیچ‌وقت",
      heartbeat ? "" : "value-dim",
    ),
    row("جاب در حال سرویس (Serving run)", heartbeat?.run_id ? String(heartbeat.run_id) : "—"),
    row("اسلات نود (Node slot)", heartbeat?.slot || status?.slot || "—"),
  );

  // -- node --------------------------------------------------------------
  const killSwitch = status?.kill_switch ?? false;
  const nodeCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "وضعیت نود اکشن (Action Node)" }),
    h("p", { class: "card-note", text: "استعلام خودکار وضعیت سلامت هر ۳۰ ثانیه از گیت‌هاب." }),
    row("فاز فعلی (Phase)", phaseLabel(status)),
    row("شناسه جاب (Run ID)", status?.run_id ? String(status.run_id) : "—"),
    row(
      "مخزن گیت‌هاب (Repository)",
      config && config.owner && config.repo ? `${config.owner}/${config.repo}` : "تنظیم نشده",
    ),
    row("آخرین استعلام (Last poll)", cd.relativeTime(status?.last_poll_unix ?? null)),
    row(
      "سهمیه باقی‌مانده API گیت‌هاب",
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
        text: killSwitch ? "لغو توقف اضطراری (Release stop switch)" : "فعال‌سازی توقف اضطراری (Engage stop switch)",
        disabled: !vault?.unlocked,
        onclick: actions.onToggleKillSwitch,
      }),
    ),
    h("p", {
      class: "card-note",
      text: "سوئیچ توقف یک نشانگر در درایو ایجاد می‌کند تا جاب فعال، جاب بعدی را دیسپچ نکند و چرخه بعد از جاب فعلی متوقف شود.",
    }),
  );

  // -- backup ledger -------------------------------------------------------
  const ledgerRows: HTMLElement[] = [];
  if (ledgerError) {
    ledgerRows.push(h("p", { class: "empty-state", text: `خطا در دریافت لیست بکاپ‌ها: ${ledgerError}` }));
  } else if (ledger.length === 0) {
    ledgerRows.push(h("p", { class: "empty-state", text: "هنوز اسنپ‌شاتی ثبت نشده است." }));
  } else {
    const table = h(
      "table",
      { class: "table-ledger" },
      h(
        "thead",
        {},
        h("tr", {}, h("th", { text: "اسنپ‌شات (Snapshot)" }), h("th", { text: "زمان ذخیره (Taken)" }), h("th", { text: "حجم (Size)" })),
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
    h("h2", { text: "دفترچه اسنپ‌شات‌ها و بکاپ‌ها (Backup Ledger)" }),
    h("p", {
      class: "card-note",
      text: `لیست اسنپ‌شات‌های ثبت شده در درایو (جدیدترین در ابتدا). تعداد مجاز نگهداری: ${config?.backup_retention ?? 20}.`,
    }),
    ...ledgerRows,
    h(
      "div",
      { class: "button-row" },
      h("button", {
        class: "action",
        type: "button",
        text: "بروزرسانی لیست بکاپ‌ها (Refresh ledger)",
        disabled: !vault?.unlocked,
        onclick: actions.onRefreshLedger,
      }),
    ),
  );

  // -- runner log tail -----------------------------------------------------
  const tailCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "خروجی زنده لاگ رانر (Runner Log Tail)" }),
    h("p", {
      class: "card-note",
      text: "مخابره شده به صورت زنده از ضربان سلامت نود در گیت‌هاب اکشن.",
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
    tailCard.append(h("p", { class: "empty-state", text: "هنوز خروجی لاگی مخابره نشده است." }));
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
    cycle_minutes: 350,
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
    h("h2", { text: "خزانه امن محلی (Local Vault)" }),
    h("p", {
      class: "card-note",
      text: "کلیدها و اطلاعات حساس شما با الگوریتم‌های فوق امنیتی Argon2id و AES-256-GCM رمزنگاری شده و توسط ماژول محافظتی ویندوز (DPAPI) فقط برای کاربر جاری در این رایانه نگهداری می‌شوند.",
    }),
  );

  vaultCard.append(
    row("وضعیت خزانه (Status)", vault?.exists ? (unlocked ? "باز شده (unlocked)" : "قفل شده (locked)") : "ایجاد نشده (not created)", unlocked ? "value-ok" : ""),
    row("قالب ساختار (Envelope)", vault?.format ?? "—"),
    row(
      "مشتق‌سازی کلید (KDF)",
      vault?.kdf
        ? `Argon2id ${Math.round(vault.kdf.m_cost_kib / 1024)} MiB, t=${vault.kdf.t_cost}, p=${vault.kdf.p_cost}`
        : kdf
          ? `calibrated: ${Math.round(kdf.m_cost_kib / 1024)} MiB, t=${kdf.t_cost}`
          : "—",
    ),
    row(
      "محافظت سیستم‌عامل (OS Protection)",
      vault?.binding_label ?? "موجود نیست",
      vault?.os_wrap ? "value-ok" : "value-warn",
    ),
    row(
      "محافظت حافظه رم (Swap Protection)",
      vault?.swap_protection ? "صفحات قفل در رم (pinned)" : "در دسترس نیست",
      vault?.swap_protection ? "value-ok" : "value-warn",
    ),
    row(
      "سلامت محافظ (Protector Health)",
      vault?.protector ?? "—",
      vault?.protector === "Healthy" ? "value-ok" : "value-warn",
    ),
    row("تعداد تغییر رمز (Rotations)", vault?.rotate_count ? String(vault.rotate_count) : "0"),
  );

  vaultCard.append(
    h("p", {
      class: "footer-note",
      id: "dpapi-caption",
      text:
        "قابلیت Windows DPAPI کلید رمزنگاری را به حساب کاربری فعلی شما متصل می‌کند که از سرقت فیزیکی اطلاعات هارد و دسترسی سایر کاربران ویندوز جلوگیری می‌کند.",
    }),
  );

  if (vault?.exists) {
    if (!unlocked) {
      const unlockField = h("input", {
        type: "password",
        id: "unlock-passphrase",
        autocomplete: "current-password",
        placeholder: "گذرواژه اصلی خزانه (Master passphrase)",
      });
      vaultCard.append(
        h("div", { class: "divider" }),
        h("label", { class: "field" }, h("span", { class: "field-label", text: "بازگشایی خزانه (Unlock)" }), unlockField),
        h(
          "div",
          { class: "button-row" },
          h("button", {
            class: "action primary",
            type: "button",
            text: "بازگشایی (Unlock)",
            onclick: () => {
              actions.onUnlock((unlockField as HTMLInputElement).value);
              (unlockField as HTMLInputElement).value = "";
            },
          }),
          h("button", {
            class: "action",
            type: "button",
            text: "بازگشایی با ویندوز (Unlock with Windows)",
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
          h("button", { class: "action", type: "button", text: "قفل کردن فوری (Lock now)", onclick: actions.onLock }),
          h("button", { class: "action", type: "button", text: "کالیبراسیون KDF (Re-calibrate)", onclick: actions.onCalibrate }),
          vault?.tamper_strikes
            ? h("button", {
                class: "action",
                type: "button",
                text: "پاک کردن هشدارها (Clear alerts)",
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
      placeholder: "حداقل ۱۲ کاراکتر ترکیبی",
    });
    vaultCard.append(
      h("div", { class: "divider" }),
      h("label", { class: "field" }, h("span", { class: "field-label", text: "ایجاد خزانه‌ی جدید (Create Vault)" }), newPass),
      h(
        "div",
        { class: "button-row" },
        h("button", {
          class: "action primary",
          type: "button",
          text: "ایجاد خزانه (Create vault)",
          onclick: () => {
            actions.onInitVault((newPass as HTMLInputElement).value);
            (newPass as HTMLInputElement).value = "";
          },
        }),
        h("button", { class: "action", type: "button", text: "سنجش سرعت و توان KDF", onclick: actions.onCalibrate }),
      ),
    );
  }

  // -- credentials ---------------------------------------------------------
  const credCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "کلیدها و توکن‌های موردنیاز (Required Credentials)" }),
    h("p", {
      class: "card-note",
      text: "مقادیر وارد شده پس از ذخیره، برای حفظ امنیت به هیچ وجه روی صفحه نمایش داده نمی‌شوند و مستقیم در خزانه رمزنگاری می‌شوند. فقط نام کلید، زمان و یادداشت ثبت می‌گردد.",
    }),
  );

  if (vault && vault.secrets.length > 0) {
    const table = h(
      "table",
      { class: "table-secrets" },
      h(
        "thead",
        {},
        h("tr", {}, h("th", { text: "نام کلید (Name)" }), h("th", { text: "آخرین ویرایش (Updated)" }), h("th", { text: "یادداشت (Note)" }), h("th", { text: "عملیات" })),
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
              text: "حذف (Delete)",
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
    credCard.append(h("p", { class: "empty-state", text: "هنوز کلیدی در خزانه ذخیره نشده است." }));
  }

  // One entry row per expected secret, so the required set is discoverable
  // rather than something the operator has to remember.
  credCard.append(h("div", { class: "divider" }));
  for (const requirement of REQUIRED_SECRETS) {
    const valueInput = requirement.multiline
      ? h("textarea", { id: `secret-value-${requirement.name}`, placeholder: "محتوای فایل کلید JSON حساب سرویس گوگل را اینجا Paste کنید" })
      : h("input", { type: "password", id: `secret-value-${requirement.name}`, placeholder: "مقدار توکن را اینجا Paste کنید" });

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
        text: "ذخیره در خزانه (Save to vault)",
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
          text: "انتخاب فایل JSON… (Choose file)",
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
      placeholder: "گذرواژه فعلی (Current passphrase)",
    });
    const newField = h("input", { type: "password", id: "rotate-new", placeholder: "گذرواژه جدید (New passphrase)" });
    credCard.append(
      h("div", { class: "divider" }),
      h("h3", { text: "تغییر گذرواژه اصلی خزانه (Rotate Master Passphrase)" }),
      h("p", {
        class: "card-note",
        text: "تغییر رمز نیازمند وارد کردن گذرواژه فعلی است تا از قفل شدن ناخواسته توسط افراد غیرمجاز جلوگیری شود.",
      }),
      h("label", { class: "field" }, h("span", { class: "field-label", text: "گذرواژه فعلی (Current)" }), rotateField),
      h("label", { class: "field" }, h("span", { class: "field-label", text: "گذرواژه جدید (New)" }), newField),
      h(
        "div",
        { class: "button-row" },
        h("button", {
          class: "action",
          type: "button",
          text: "تغییر و ثبت رمز جدید (Rotate)",
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
      h("h3", { class: "danger-text", text: "حذف و نابودی کامل خزانه (Destroy Vault)" }),
      h("p", {
        class: "card-note",
        text: "عملیات پاکسازی غیرقابل بازگشت: با حذف کلید محافظ، تمام اطلاعات رمزنگاری‌شده بلافاصله نابود و غیرقابل بازیابی می‌شوند.",
      }),
      (() => {
        const destroyField = h("input", {
          type: "password",
          id: "destroy-passphrase",
          placeholder: "جهت تأیید نهایی، گذرواژه را وارد کنید",
        });
        return h("div", {},
          destroyField,
          h("div", { class: "button-row" },
            h("button", {
              class: "action danger",
              type: "button",
              text: "نابودی همیشگی خزانه (Destroy vault)",
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
    h("h2", { text: "تنظیمات مخزن و چرخه اکشن (Repository & Cycle Settings)" }),
    h("p", {
      class: "card-note",
      text: "تمامی نودها و هاستینگ روی این مخزن مشترک اجرا می‌شوند. جاب فعلی پیش از اتمام، جاب بعدی را در اسلات آماده فراخوانی می‌کند تا هاستینگ پیوسته و بدون وقفه ادامه یابد.",
    }),
    h(
      "div",
      { class: "field-grid" },
      field("cfg-owner", "مالک مخزن گیت‌هاب (GitHub Owner)", cfg.owner, "نام کاربری یا سازمان در گیت‌هاب (مثال: alirezapiri0)"),
      field("cfg-repo", "نام مخزن گیت‌هاب (Repository Name)", cfg.repo, "نام ریپازیتوری که ورک‌فلو در آن قرار دارد (مثال: node-runner)"),
      field("cfg-workflow", "نام فایل ورک‌فلو (Workflow File)", cfg.workflow_file, "مسیر فایل ورک‌فلو در پوشه .github/workflows (پیش‌فرض runner.yml)"),
      field("cfg-cycle", "مدت زمان هر چرخه به دقیقه (Cycle Length)", cfg.cycle_minutes, "مدت زمان اجرای هر جاب؛ حداکثر ۳۵۰ دقیقه (برای سقف ۶ ساعته اکشن)", "number"),
      field("cfg-poll", "فاصله استعلام وضعیت به ثانیه (Poll Interval)", cfg.poll_seconds, "بررسی سلامت جاب از گیت‌هاب (حداقل ۱۰ ثانیه، پیش‌فرض ۳۰)", "number"),
      field("cfg-lock", "قفل خودکار خزانه به دقیقه (Auto-lock Minutes)", cfg.auto_lock_minutes, "مدت زمان عدم فعالیت تا قفل شدن مجدد خزانه امن", "number"),
      field("cfg-workload", "الگوی پروسس هاستینگ (Workload Pattern)", cfg.workload_pattern, "نام پروسس یا برنامه‌ای که قبل از اسنپ‌شات موقتاً فریز می‌شود (اختیاری)"),
      field("cfg-tunnel", "دامنه تانل کلودفلر (Tunnel Hostname)", cfg.tunnel_hostname, "آدرس دامنه پایدار ثبت شده (مثال: node.yourdomain.com)"),
      field("cfg-folder", "شناسه پوشه گوگل درایو (Drive Folder ID)", cfg.drive_folder_id, "آیدی پوشه اشتراک‌گذاری شده در گوگل درایو جهت نگهداری دائمی بکاپ‌ها"),
      field("cfg-retention", "تعداد بکاپ‌های نگهداری‌شده (Backup Retention)", cfg.backup_retention, "تعداد آخرین اسنپ‌شات‌های حفظ شده در درایو (پیش‌فرض ۲۰)", "number"),
    ),
    h(
      "div",
      { class: "button-row" },
      h("button", {
        class: "action primary",
        type: "button",
        text: "ذخیره تنظیمات (Save settings)",
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
            cycle_minutes: readNumber("cfg-cycle", 350),
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
        text: "تزریق کلیدها به سکرت‌های مخزن گیت‌هاب (Inject credentials)",
        disabled: !unlocked,
        onclick: actions.onInjectSecrets,
      }),
    ),
    h("p", {
      class: "footer-note",
      text: "با زدن دکمه تزریق، کلیدهای ذخیره شده در خزانه با کلید عمومی مخزن گیت‌هاب رمزنگاری شده و مستقیماً به سکرت‌های اکشن ارسال می‌شوند تا جاب‌ها بدون نیاز به ورود دستی، از آن‌ها استفاده کنند.",
    }),
  );

  // -- diagnostics ---------------------------------------------------------
  const infoCard = h(
    "div",
    { class: "card" },
    h("h2", { text: "عیب‌یابی و وضعیت سیستم (Diagnostics)" }),
    row("نسخه برنامه (Application version)", info?.version ?? "—"),
    row("مسیر پوشه داده‌ها (Data directory)", info?.data_dir ?? "—"),
    row("مسیر فایل خزانه (Vault file)", info?.vault_path ?? "—"),
    row("محافظت کلید ویندوز (OS key protection)", info?.os_protection ? "فعال (available)" : "غیرفعال (unavailable)", info?.os_protection ? "value-ok" : "value-warn"),
    row("محافظت رم (Swap protection)", info?.swap_protection ? "فعال (available)" : "غیرفعال (unavailable)", info?.swap_protection ? "value-ok" : "value-warn"),
    row("تست ماژول محافظ (Protector probe)", info?.protector_status ?? "—"),
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
    placeholder: "جستجو و فیلتر لاگ‌ها (Filter)...",
    value: needle,
  }) as HTMLInputElement;
  searchInput.addEventListener("input", () => actions.onSearch(searchInput.value));

  const toolbar = h(
    "div",
    { class: "logs-toolbar" },
    h("button", {
      class: paused ? "action primary" : "action",
      type: "button",
      text: paused ? "ادامه (Resume)" : "توقف موقت (Pause)",
      onclick: actions.onTogglePause,
    }),
    searchInput,
    h("button", { class: "action", type: "button", text: "کپی لاگ‌ها (Copy)", onclick: actions.onCopy }),
    h("button", { class: "action ghost", type: "button", text: "پاک کردن (Clear)", onclick: actions.onClear }),
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
    view.append(h("p", { class: "empty-state", text: "هنوز گزارش لاگی ثبت نشده است." }));
  }

  return h(
    "div",
    {},
    toolbar,
    h("p", {
      class: "card-note",
      text: "گزارش لاگ نرم‌افزار: وقایع خزانه‌ی امن، وضعیت استعلام و رویدادهای انتقال جاب‌ها. خروجی لاگ زنده‌ی خود نود نیز در تب داشبورد نمایش داده می‌شود.",
    }),
    view,
  );
}
