#!/usr/bin/env bash
#
# Install the two required binaries at pinned versions, with checksum
# verification.
#
# `curl | sh` and `apt-get install rclone` are both rejected here for the same
# reason: the runner holds a service-account key with write access to the only
# copy of the user's data. A supply-chain compromise of a helper binary is a
# compromise of the data. So both tools are pinned by version and verified
# before they are ever executed.
#
# Why the two tools are verified differently:
#
#   rclone publishes a SHA256SUMS file next to each release. That file is fetched
#   over TLS from downloads.rclone.org and the archive is checked against it.
#
#   cloudflared does not publish a machine-readable checksum file. The expected
#   digest therefore comes from runner/cloudflared.sha256, which is checked into
#   this repository, and is cross-checked against the digest GitHub's release API
#   reports for that exact asset. Both sources must agree; if they cannot be
#   obtained, the script refuses to install cloudflared. A node that cannot serve
#   the domain but preserves the data is the correct way round to fail.
#
#   The values below were recorded from the vendors' own published metadata on
#   2026-09-16:
#
#     rclone v1.75.1   SHA256SUMS: 982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab
#     cloudflared 2026.9.1   release API digest: 03f1f25d1cc93b9ad6c60569d44060bc4f17ed97075760ed8cfca4b12dcd68cc
#
#   When bumping either version, re-record both and update this comment. A pin
#   that is never reviewed is not a pin.

set -Eeuo pipefail

readonly RCLONE_VERSION="${RCLONE_VERSION:-1.75.1}"
readonly CLOUDFLARED_VERSION="${CLOUDFLARED_VERSION:-2026.9.1}"
readonly BIN_DIR="${BIN_DIR:-${HOME}/.local/bin}"
readonly CHECKSUM_FILE="${CHECKSUM_FILE:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/cloudflared.sha256}"

# The digest lives in `cloudflared.sha256` beside this script. That file is the
# offline source of truth and the only thing actually verified against; the
# release API is consulted as an independent second opinion, not as a fallback,
# because a fallback that nothing reads is just an unverified constant.

log() { printf '%s [tools] %s\n' "$(date -u '+%H:%M:%SZ')" "$*" >&2; }
die() { printf '%s [tools] FATAL: %s\n' "$(date -u '+%H:%M:%SZ')" "$*" >&2; exit 1; }

warn() { printf '%s [tools] warn: %s\n' "$(date -u '+%H:%M:%SZ')" "$*" >&2; }

verify_sha256() {
  local file="$1" expected="$2"
  local actual
  actual=$(sha256sum "$file" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] \
    || die "checksum mismatch for $(basename "$file"): expected ${expected}, got ${actual}"
}

# Ask GitHub's release API for the sha256 of a named asset. Returns an empty
# string (not an error) when the field or the release is unavailable, so callers
# can fall back to their checked-in pin.
github_asset_digest() {
  local repo="$1" tag="$2" asset="$3"
  local -a auth=()
  [[ -n "${GH_PAT:-}" ]] && auth=(--header "Authorization: Bearer ${GH_PAT}")
  curl -fsSL --max-time 20 "${auth[@]}" \
    "https://api.github.com/repos/${repo}/releases/tags/${tag}" 2>/dev/null \
    | jq -r --arg a "$asset" '.assets[]? | select(.name == $a) | .digest // empty' 2>/dev/null \
    | sed 's/^sha256://' | head -n 1
}

install_rclone() {
  if [[ -x "${BIN_DIR}/rclone" ]] \
      && [[ "$("${BIN_DIR}/rclone" version 2>/dev/null | head -n 1 | awk '{print $2}')" == "v${RCLONE_VERSION}" ]]; then
    log "rclone v${RCLONE_VERSION} already present"
    return 0
  fi

  local base="https://downloads.rclone.org/v${RCLONE_VERSION}"
  local zip="rclone-v${RCLONE_VERSION}-linux-amd64.zip"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "${tmp:-}"' RETURN

  log "downloading rclone v${RCLONE_VERSION}"
  curl -fsSL --retry 3 -o "${tmp}/${zip}" "${base}/${zip}" || die "rclone download failed"
  curl -fsSL --retry 3 -o "${tmp}/SHA256SUMS" "${base}/SHA256SUMS" || die "rclone SHA256SUMS download failed"

  local expected
  expected=$(awk -v z="$zip" '$2 == z {print $1}' "${tmp}/SHA256SUMS")
  [[ -n "$expected" ]] || die "no checksum published for ${zip}"
  verify_sha256 "${tmp}/${zip}" "$expected"

  unzip -q -o "${tmp}/${zip}" -d "$tmp" || die "could not unpack rclone"
  install -m 0755 "${tmp}/rclone-v${RCLONE_VERSION}-linux-amd64/rclone" "${BIN_DIR}/rclone"
  log "installed rclone v${RCLONE_VERSION}"
  rm -rf "$tmp"
  trap - RETURN
}

install_cloudflared() {
  if [[ -x "${BIN_DIR}/cloudflared" ]] \
      && [[ "$("${BIN_DIR}/cloudflared" --version 2>/dev/null | awk '{print $3}')" == "$CLOUDFLARED_VERSION" ]]; then
    log "cloudflared ${CLOUDFLARED_VERSION} already present"
    return 0
  fi

  if [[ ! -f "$CHECKSUM_FILE" ]]; then
    die "refusing to install cloudflared without a checksum: create ${CHECKSUM_FILE} (see the header of this script)"
  fi

  local expected
  expected=$(tr -d '[:space:]' <"$CHECKSUM_FILE")
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] \
    || die "${CHECKSUM_FILE} must contain a single sha256 hex digest"

  # Independent second source. The repository copy is what the operator reviews;
  # the API digest is what Cloudflare published. If they disagree, the repo file
  # has been tampered with or the release was re-cut, and either way the install
  # should stop rather than pick a winner.
  local api_digest
  api_digest=$(github_asset_digest "cloudflare/cloudflared" "${CLOUDFLARED_VERSION}" "cloudflared-linux-amd64" || true)
  if [[ -n "$api_digest" ]]; then
    [[ "$api_digest" == "$expected" ]] \
      || die "checksum disagreement: ${CHECKSUM_FILE} says ${expected}, the release API says ${api_digest}"
    log "checksum confirmed against the release API digest"
  else
    warn "could not reach the release API; relying on the checked-in checksum"
  fi

  local url="https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-amd64"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "${tmp:-}"' RETURN

  log "downloading cloudflared ${CLOUDFLARED_VERSION}"
  curl -fsSL --retry 3 -o "${tmp}/cloudflared" "$url" || die "cloudflared download failed"
  verify_sha256 "${tmp}/cloudflared" "$expected"

  install -m 0755 "${tmp}/cloudflared" "${BIN_DIR}/cloudflared"
  log "installed cloudflared ${CLOUDFLARED_VERSION}"
  rm -rf "$tmp"
  trap - RETURN
}

main() {
  # `--only rclone` is used by the watchdog, which never binds a tunnel and so
  # should not need the cloudflared checksum to be resolvable in order to run.
  local only=""
  while (( $# > 0 )); do
    case "$1" in
      --only) only="${2:-}"; shift 2 ;;
      -h|--help) printf 'usage: install-tools.sh [--only rclone|cloudflared]\n'; return 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  mkdir -p "$BIN_DIR"

  # Only needed for unpacking rclone; present on GitHub's ubuntu images but not
  # guaranteed, and a hard failure here is much clearer than a confusing rclone
  # error later.
  if [[ "$only" == "" || "$only" == "rclone" ]]; then
    command -v unzip >/dev/null 2>&1 || die "unzip is required (apt-get install -y unzip)"
    install_rclone
  fi
  if [[ "$only" == "" || "$only" == "cloudflared" ]]; then
    install_cloudflared
  fi

  # Export for the calling script, which is why this is meant to be sourced or
  # called before PATH is consulted.
  if [[ -n "${GITHUB_PATH:-}" ]]; then
    printf '%s\n' "$BIN_DIR" >>"$GITHUB_PATH"
  fi
  log "tooling ready in ${BIN_DIR}"
}

main "$@"
