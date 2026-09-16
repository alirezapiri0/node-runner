#!/usr/bin/env bash
# shellcheck shell=bash
#
# Content manifest generation and verification.
#
# The manifest is the only reason a backup can be trusted. `rclone copy` exiting
# zero means the transfers it attempted succeeded; it says nothing about whether
# the source tree itself was consistent, and nothing about files that changed
# underneath it. Hashing the tree before and after the upload is what converts
# "the command returned 0" into "these exact bytes are now in Drive".

# Emit a sorted `sha256sum`-format manifest of every regular file under $1.
#
# Uses NUL-delimited pipelines throughout because a workload's filenames are
# attacker-adjacent at worst and merely arbitrary at best: a newline in a path
# would otherwise be parsed as a second record and silently corrupt the manifest.
manifest_write() {
  local root="$1" out="$2"
  [[ -d "$root" ]] || die "manifest: not a directory: $root"

  local tmp="${out}.tmp"
  (
    cd "$root" || exit 1
    find . -type f -printf '%P\0' \
      | LC_ALL=C sort -z \
      | xargs -0 -r --no-run-if-empty sha256sum
  ) >"$tmp" || die "manifest: failed to hash $root"

  mv -f "$tmp" "$out"
  printf '%s\n' "$(wc -l <"$out" | tr -d ' ')"
}

# Verify a tree against a manifest. Exits non-zero on any mismatch.
manifest_verify() {
  local root="$1" manifest="$2"
  [[ -f "$manifest" ]] || die "manifest: missing $manifest"

  local failed
  if ! failed=$(cd "$root" && sha256sum --quiet -c "$manifest" 2>&1); then
    printf '%s\n' "$failed" | head -n 20 >&2
    die "manifest: verification failed for $root"
  fi
}

# A cheap fingerprint of the manifest itself, recorded in the commit record so
# that a restore can assert it restored the tree the predecessor actually
# vouched for, not merely *a* tree.
manifest_digest() {
  sha256sum "$1" | awk '{print $1}'
}

# Count of files and total bytes, for the commit record and the UI ledger.
manifest_stats() {
  local root="$1"
  local files bytes
  files=$(find "$root" -type f -printf '.' | wc -c | tr -d ' ')
  bytes=$(du -sb "$root" 2>/dev/null | awk '{print $1}')
  printf '%s %s\n' "$files" "${bytes:-0}"
}
