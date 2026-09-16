# Setup

Five stages. Stage 1 is where most people get stuck, and the reason is a Google
platform rule rather than anything in this code, so it is worth reading carefully.

---

## 1. Google Drive access

### 1a. Create the service account

In the [Google Cloud console](https://console.cloud.google.com/):

1. Create (or pick) a project.
2. **APIs & Services → Library → Google Drive API → Enable.** Without this,
   rclone fails with a 403 that does not mention the API.
3. **APIs & Services → Credentials → Create credentials → Service account.**
   Give it no roles; it needs no IAM permissions, only Drive access.
4. Open the service account → **Keys → Add key → Create new key → JSON.**
   Download it. This file is the `RCLONE_SERVICE_ACCOUNT_JSON` value.
5. Note the service account's email: `<name>@<project>.iam.gserviceaccount.com`.

### 1b. Give it somewhere to write — and read this part

**A service account has no Drive storage quota of its own.** Files it creates are
owned by the service account, and a service account cannot own files, so the
upload fails with:

```
Error 403: Service Accounts do not have storage quota.
Leverage shared drives, or use OAuth delegation instead.
```

This is not an rclone bug and no flag fixes it. Sharing a folder in your personal
My Drive with the service account as Editor is **not sufficient**: the service
account can see the folder, and still cannot create a file in it. Choose one of
three options.

| Option | Works when | Trade-off |
| --- | --- | --- |
| **A. Workspace Shared Drive** (recommended) | You have Google Workspace | Needs a Workspace seat. Files are owned by the Shared Drive, so the quota problem disappears entirely. |
| **B. Domain-wide delegation** | Google Workspace | The service account impersonates your user; uploads are owned by you. Needs admin-console setup and rclone's `impersonate` setting, which this project does not configure by default. |
| **C. User OAuth instead of a service account** | Any Google account | Reintroduces an OAuth refresh token, which is what the service account was meant to avoid. Fine if your OAuth app is *published*; in *testing* mode refresh tokens expire every 7 days and the loop dies weekly. |

**For option A:**

1. Create a Shared Drive.
2. Right-click it → **Manage members** → add the service account email as
   **Content manager**.
3. Open the Shared Drive and copy the folder ID from the URL:
   `https://drive.google.com/drive/folders/`**`<THIS>`** — for a Shared Drive root,
   use the ID of any folder inside it, which is what the node will write into.
4. That ID is the `GDRIVE_ROOT_FOLDER_ID` variable in stage 3.

Create the structure the node expects inside that folder (or let the first cycle
create it — see stage 4):

```
<shared drive folder>/
  heartbeat.json            written by the node, read by the app
  KILLSWITCH.json           written by the app, read by the node
  state/lease.json          single-writer lease
  state/COMMIT/<ts>.json    one per committed snapshot
  state/ACK/<ts>.json       successor's acknowledgement
  snapshots/<ts>/           immutable snapshots
```

Verify before going further:

```bash
export RCLONE_CONFIG_GDRIVE_TYPE=drive
export RCLONE_CONFIG_GDRIVE_SCOPE=drive
export RCLONE_CONFIG_GDRIVE_SERVICE_ACCOUNT_FILE=/path/to/key.json
export RCLONE_CONFIG_GDRIVE_ROOT_FOLDER_ID=<folder id>
rclone lsd gdrive:
```

An empty listing and no error is success. `403` means the folder was not shared
with the service account; `storage quota` means you are on option B or C.

---

## 2. Cloudflare named tunnel

The tunnel token is what makes the public hostname stable across migrations: the
hostname is bound to the tunnel, and whichever node holds the token serves it.
Two nodes holding the same token is not a conflict — Cloudflare load-balances
across connectors of the same tunnel, which is exactly what makes the handover
seamless.

1. In the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com/):
   **Networks → Tunnels → Create a tunnel → Cloudflared.**
2. Name it (e.g. `node-runner`). Skip the OS instructions.
3. **Public hostname → Add.** Pick the domain, choose a subdomain, and set the
   service to whatever your workload listens on, e.g. `http://localhost:8080`.
   This is the immutable endpoint the app displays.
4. Copy the **connector token** from the install command
   (`cloudflared tunnel run --token <TOKEN>`). That token is `CF_TUNNEL_TOKEN`.

Notes:

* The token embeds the tunnel ID and secret. It is scoped to this one tunnel, and
  it is the only credential in this system that has to appear in a process
  argument list, because `cloudflared` offers no other interface for it. Rotate it
  from the dashboard if a runner is ever compromised. See
  [SECURITY.md](SECURITY.md#the-tunnel-token-and-argv).
* A remotely-managed (token) tunnel needs no `cloudflared tunnel login` and no
  `cert.pem`, which is why this project uses one.

---

## 3. GitHub repository and credentials

### 3a. Repository

Create **one private repository** for the node. Do not create a repository per
cycle — see [COMPLIANCE.md](COMPLIANCE.md) for why that design was rejected.

Copy this project's contents into it, so that `.github/workflows/runner.yml` and
`runner/` sit at the repository root.

### 3b. Workload

```bash
cp runner/workload.example.sh runner/workload.sh
```

Edit it, commit it, and set the `WORKLOAD_PATTERN` repository variable to a
`pgrep -f` pattern that matches it (e.g. `workload\.sh`). `runner/workload.sh`
is intentionally not in version control of this project, because on a real
deployment it is your code, not this project's.

If you have no workload yet, leave `WORKLOAD_PATTERN` empty: the node still
serves the tunnel, still snapshots `WORK_DIR`, and still migrates.

### 3c. Secrets

**Settings → Secrets and variables → Actions.** Add these as **secrets**:

| Secret | Value |
| --- | --- |
| `GH_PAT` | The fine-grained token from 3d |
| `RCLONE_SERVICE_ACCOUNT_JSON` | The entire JSON key file from 1a, verbatim |
| `CF_TUNNEL_TOKEN` | The tunnel token from stage 2 |

And these as **variables**:

| Variable | Value |
| --- | --- |
| `GDRIVE_ROOT_FOLDER_ID` | The Shared Drive folder ID from 1b |
| `WORKLOAD_PATTERN` | `pgrep -f` pattern, or empty |

The desktop app can inject the three secrets for you
(`secrets_inject`, Settings tab) using the same synchronous encryption GitHub
requires. Either path works; setting them by hand once is less to go wrong.

### 3d. Personal access token

Use a **fine-grained** token scoped to the node repository only:

| Permission | Why | Needed by |
| --- | --- | --- |
| **Actions: Read and write** | Dispatch the successor, read run status | node, watchdog, app |
| **Secrets: Read and write** | Inject secrets from the desktop app | app only |
| **Metadata: Read** | Mandatory, always granted | all |

Explicitly **not** needed: `Administration` (repository creation). The original
specification required it; the handover implemented here does not, and that is
the single largest reduction in blast radius in this design. If your token has
repository-creation rights, it has more authority than anything in this project
uses.

Classic tokens work too: `workflow` + `repo`. They are account-scoped, so
prefer fine-grained.

### 3e. cloudflared checksum

`runner/install-tools.sh` refuses to install `cloudflared` without a trusted
sha256, because a compromised helper binary that runs beside the Drive key is a
compromise of the data. A digest for `2026.9.1` is already committed in
`runner/cloudflared.sha256`, and the script cross-checks it against the digest
GitHub's release API reports for that asset.

When you bump `CLOUDFLARED_VERSION`, re-record it:

```bash
curl -fsSL "https://api.github.com/repos/cloudflare/cloudflared/releases/tags/2026.9.1" \
  | jq -r '.assets[] | select(.name == "cloudflared-linux-amd64") | .digest'
```

rclone needs no such file: it verifies against the `SHA256SUMS` published
alongside its own release.

---

## 4. Start the loop

The loop needs no bootstrap script. Either:

* **Actions tab → node → Run workflow**, slot `blue`, reason `bootstrap`; or
* wait up to 30 minutes: the watchdog finds no `heartbeat.json` and dispatches
  the first node itself.

The first cycle restores nothing (there is no committed snapshot yet) and starts
from an empty work directory. That is the expected first run.

**One caveat that will bite you in two months:** GitHub disables scheduled
workflows in a repository that has had no repository activity for 60 days. This
node never pushes a commit, so if nothing else touches the repository, the
watchdog's cron can be switched off by GitHub — and then a node that dies without
handing over stays dead. Either keep the repository otherwise active, or make a
trivial commit monthly, or use the desktop app's Force Migration button as your
periodic heartbeat. The app also reads the repository's Actions settings on
demand, so a disabled schedule is visible from the dashboard.

---

## 5. Build the desktop app

Prerequisites: Rust stable, Node 20+, and on Windows the MSVC build tools with
the Windows SDK, plus WebView2 (preinstalled on Windows 11 and current Windows
10).

```bash
cd desktop
npm ci

# Development: loads the frontend from Vite on :1420
npm run tauri:dev

# Release: bundles the frontend, then builds the executable and the installer
npm run tauri:build
```

Artifacts (under `desktop/target/`, because `desktop/` is the Cargo workspace
root — the target directory is *not* under `src-tauri/`):

* `desktop/target/release/node-runner.exe` — this is the portable binary. Copy it
  anywhere; it carries its frontend inside. It relies on the WebView2 runtime
  being present, which it is on any updated Windows 10/11.
* `desktop/target/release/bundle/nsis/*.exe` — an installer, which is the variant
  that can bootstrap WebView2 on a machine that lacks it.

The same two paths are published as artifacts of the `ci` workflow on Windows,
so a machine without the MSVC toolchain can still obtain the binary.

To look at the interface *without* the Rust backend there is a development
harness:

```bash
cd desktop
npm run dev          # then open http://127.0.0.1:1420/dev/harness.html
```

It loads the real `index.html` shell and the real `src/` modules, and replaces
only the Tauri command layer with canned data. Two reasons this earns its place:
a rendering change can be checked on a machine that cannot build Tauri at all,
and a panel that renders nothing fails silently against a green typecheck -- which
is how a blank Settings panel reached a release. Nothing in `src/` imports the
harness and it is not part of the bundle.

Then, in the app:

1. **Settings → Vault → Initialise.** Choose a master passphrase. Argon2id
   calibration runs first (a few seconds) and picks memory/time costs for this
   machine; the vault is then sealed and the master key is wrapped with DPAPI so
   you can unlock it in future without retyping the passphrase on this machine.
2. **Settings → Secrets.** Add `GH_PAT`, `RCLONE_SERVICE_ACCOUNT_JSON` and
   `CF_TUNNEL_TOKEN`, plus the repository (`owner/name`) and the tunnel hostname.
3. **Settings → Inject into repository** to publish the secrets, if you did not
   set them by hand in 3c.
4. **Dashboard** should show the node, a countdown derived from the server's own
   clock (not the local one), the endpoint with its copy button, and the backup
   ledger.

The vault is written to
`%APPDATA%\dev.noderunner.desktop\vault.nrv`. Back it up only in its encrypted
form; it is useless without both the passphrase and your Windows profile.
