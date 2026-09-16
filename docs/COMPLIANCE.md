# Compliance, and the one design change that is not a technicality

**This is not legal advice, and it is not a substitute for reading GitHub's
current Acceptable Use Policies and Terms of Service.** The policies are the
authority; this document explains what in the original design runs into them and
what changed as a result. I could not fetch the policy text from the environment
this was written in, so the characterisations below are of *policy intent*, not
quotations, and you should verify them against the live documents before relying
on any of it.

## The risk in the original specification

The specification's handover created a **new public repository every 5 hours 40
minutes**, injected a repository-creation-scoped PAT, the Drive service-account
key and the tunnel token into it, and repeated forever. Two independent problems:

### 1. Credential concentration (fixable, and fixed)

Every cycle would place the operator's most privileged credential into a
world-readable repository's secret store, fresh, forever. GitHub repository
secrets are write-only through the API and encrypted with the repository's public
key, so they are not *readable* by a third party — but that is a much weaker
property than "the credential was never there". Public repositories also have
attributes the operator does not control: forking, and the fact that anyone can
open a PR or trigger a `workflow_dispatch` on a fork whose workflow file they
modify. A PAT with repository-creation scope is account-shaped authority; its
blast radius is every repository the operator can reach, not one.

**Fixed by:** one long-lived private repository, secrets configured once by the
operator, handover by `workflow_dispatch`. The PAT now needs `actions:write` and
`secrets:write` on a single repository and nothing account-scoped. There is no
repository creation anywhere in this codebase, and no code path that writes a
credential into another repository.

### 2. Purpose of use (not entirely fixable — read this)

GitHub's Acceptable Use Policies restrict Actions to purposes connected to the
software in the repository it runs in — building, testing, packaging, releasing,
deploying. Using Actions as general-purpose compute unrelated to the repository's
own software, and in particular arrangements designed to run continuously or to
circumvent the usage limits attached to it, is the area the policy addresses.
The failure mode is not a broken build. It is **account suspension**, and
suspension takes the repositories, the issues, and your ability to export any of
it with it.

A self-rotating node whose only purpose is to stay alive is closer to that pattern
than to a build pipeline, no matter how cleanly the handover is implemented. This
project can remove the credential problem; **it cannot make a perpetual
general-purpose compute loop into something the policy is happy with.** That
judgement is yours, and it depends on facts I do not have: your account type, your
plan, and what the workload actually does.

## What this implementation does to reduce the risk

| Original design | This implementation |
| --- | --- |
| New public repo every cycle | One private repo, unchanged between cycles |
| PAT needs repository creation | PAT needs `actions:write` on one repo |
| Secrets re-injected every cycle | Secrets configured once, by the operator |
| Secrets end up in `N` repositories | Secrets exist in exactly one place |
| Repository history fragmented across `N` repos | One history, one audit trail |
| Workflow file re-pushed and re-triggered each cycle | Workflow file changes only when the operator changes it |

The migration is unchanged. The successor still starts before the predecessor
exits, the endpoint is still continuously bound, the state still moves every cycle
— the only thing that stopped happening is repository churn and the credential
copying that came with it.

## What is still not resolved

1. **Runtime.** The node runs about 340 minutes out of every ~345. This is close
   to continuous, and it is the property the policy area is concerned with. A
   less aggressive configuration is *safe* to run: raise `CYCLE_MINUTES`'s
   *interval* by not handing over every cycle — dispatch one node per day instead
   of chaining forever — and the system still works, with fresh state restored
   each time. That is the single most effective change if you want to stay
   clearly inside the policy, and it costs you the "continuous" property only.
2. **Scheduled workflows.** GitHub disables schedules after 60 days without
   repository activity, and the watchdog depends on one. See
   [SETUP.md](SETUP.md#4-start-the-loop).
3. **Your plan's limits.** Actions minutes, storage, and concurrency limits differ
   by account type, and a loop that runs 98% of the day will consume them
   differently from a CI that runs on push.

## Recommended dispositions

In order of how much I would endorse them:

1. **Use this design for a workload that is genuinely tied to the repository's
   software** — a soak test, a long integration run, a deployment that needs to
   stay warm. The policy is written for exactly this, and nothing here is a
   workaround.
2. **Dispatch nodes on demand rather than chaining them.** Keep every mechanism —
   the freeze, the snapshot, the commit records, the manifest verification — and
   change only what starts the next node. The state machine does not care whether
   the successor arrives five hours later or five days later.
3. **If you need continuous compute for its own sake, buy continuous compute.** A
   small VPS or a container host is cheaper than the account risk, and it removes
   this document from your life entirely. The security architecture built here —
   Argon2id, DPAPI-wrapped DEK, immutable verified snapshots — ports to it
   unchanged; only `runner/` becomes unnecessary, because there is no migration
   left to perform.
4. **If you proceed as specified anyway**, do it on an account you can afford to
   lose, keep the kill switch reachable, and export anything you care about out of
   the repository rather than leaving it only there.

## Data handling summary

For a compliance reviewer, the facts as implemented:

* **Locally:** all credentials encrypted at rest (Argon2id → AES-256-GCM, DEK also
  wrapped with DPAPI). No plaintext credential is written to disk by this
  application. `no_plaintext_reaches_disk` is a test, not a promise.
* **To Google Drive:** snapshot contents in plaintext, plus unencrypted metadata
  (commit records, lease, heartbeat, kill switch). No credentials are ever written
  to Drive.
* **To GitHub:** the PAT and the service-account key as repository secrets,
  encrypted to the repository public key before transmission. Workflow runs
  record which slot ran when and the lifecycle log tail (redacted for anything
  matching a token or private key) in the heartbeat.
* **Retention:** 20 snapshots by default, oldest pruned first, and the snapshot
  just committed is never prunable regardless of clock skew. Commit records and
  acknowledgements are not pruned at all.
* **Deletion:** `vault_destroy` removes the vault, its backup generation and the
  DPAPI-encrypted material. The tamper ledger is kept, deliberately, so that
  destruction is auditable.
