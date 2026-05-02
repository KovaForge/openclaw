---
summary: "Gatekeeper privileged actions: Discord-mediated approvals for narrow local helper verbs"
read_when:
  - Designing or configuring privileged actions
  - Reviewing Gatekeeper approval security
  - Diagnosing privileged action helper setup
title: "Privileged actions"
---

Privileged actions are the Gatekeeper approval path for narrow local helper verbs. They are separate from normal `exec` and from `~/.openclaw/exec-approvals.json`.

The MVP supports one mutating verb:

- `homebrew.install(formula)`

It also includes the planned local diagnostic command:

- `privileged doctor`

Phase 2B pass 1 adds repo-native TypeScript helper source and unit tests only. It does not install the helper, write sudoers, modify `/usr/local`, `/Library`, or `/var/run`, or run anything as root.

## Security model

Privileged actions approve a structured action, not a shell command. Discord approval must authorize the exact bound action tuple and the helper identity that will execute it later.

The MVP intentionally does not support:

- sudo password prompts in Discord
- arbitrary root shell
- `allow-always` for privileged actions
- channel-visible privileged approvals
- `homebrew.update`, `homebrew.upgrade`, service restart, or LuLu write verbs

The config schema hard-codes `passwordPrompt: false` and only accepts `approval.target: "dm"`.

## Config

```json5
{
  privilegedActions: {
    enabled: true,
    passwordPrompt: false,
    approval: {
      target: "dm",
      approvers: ["195468996584275968"],
      agentFilter: ["vladislava"],
      sessionFilter: ["discord:"]
    },
    helper: {
      mode: "sudoers",
      path: "/usr/local/libexec/openclaw-privileged-helper",
      brewPath: "/opt/homebrew/bin/brew",
      configPath: "/Library/Application Support/OpenClaw/privileged-actions.json"
    },
    verbs: {
      homebrew: {
        install: {
          enabled: true,
          formulaAllowlist: ["wget"]
        }
      }
    }
  }
}
```

`privilegedActions` must not write or tighten `tools.exec.*` or `~/.openclaw/exec-approvals.json`. Cron/background jobs continue to use normal exec policy. Reviews and tests for this namespace should treat any privileged-action change to `tools.exec.security`, `tools.exec.ask`, or host `askFallback` defaults as a release blocker.

`helper.brewPath` must be pinned to one of the known Homebrew prefixes:

- `/usr/local/bin/brew`
- `/opt/homebrew/bin/brew`

The Phase 2B helper must use this configured/default pinned path directly. It must not resolve `brew` through `PATH` and must reject arbitrary executable paths.

## Helper implementation

The helper source lives at `src/infra/privileged-action-helper.ts`. The implementation language is TypeScript because OpenClaw is already TypeScript, the helper can reuse the same canonical action normalization and binding code as the runtime, and the security boundary is testable without adding a second toolchain.

The intended installed helper path remains exact and sudoers-bound:

```text
/usr/local/libexec/openclaw-privileged-helper
```

Phase 2B pass 1 is source/docs/tests only. Packaging and installation must be reviewed separately before any file is copied to that path.

The helper CLI accepts only these shapes:

```text
openclaw-privileged-helper --request <request-id>
openclaw-privileged-helper doctor --json
```

Request argv contains only the request ID. The helper reads the verb and formula from the bound request record, reconstructs the binding hash locally, verifies the authorized approver against trusted config, and consumes the request atomically before returning an execution plan.

The helper must execute Homebrew directly through the pinned `helper.brewPath` value. It must not invoke a shell, use `/usr/bin/env`, search `PATH`, or accept an executable path from the request argv.

## Formula normalization

`homebrew.install(formula)` accepts formula names that match:

```text
[a-zA-Z0-9@._+-]
```

Additional rules:

- max length: 128 characters
- reject empty strings
- reject `.` and `..`
- reject `/` and `\`
- reject whitespace, control characters, non-ASCII, shell metacharacters, and leading `-`

Examples accepted:

- `wget`
- `openssl@3`
- `node@20`
- `foo_bar`
- `foo-bar`
- `foo.bar`
- `foo+bar`

The canonical display is generated from the same normalized object that is bound for approval:

```text
homebrew.install  |  wget
```

## Binding and replay model

The planned execution model is server-side consumed approval/request records. Helper implementation should store pending requests in an OpenClaw-controlled or root-owned state directory and consume them atomically before execution.

The Phase 2A binding model includes:

- request ID
- decision nonce
- approver Discord ID
- approval timestamp
- verb
- normalized args
- target host/node
- agent ID
- session key hash, not raw session key
- helper path
- helper version/hash
- expiry

Execution must reject:

- expired request
- reused request
- mismatched verb, args, host/node, agent, session hash, or helper identity
- unauthorized approver
- missing or malformed decision

## Discord MVP UX

Privileged approvals are DM-only. If a request originates from a server channel, the approval should be routed to DM for security.

Card content should use privileged-specific copy:

```text
WARNING: PRIVILEGED ACTION
homebrew.install  |  wget
Requested by: Vladislava - Target: Mike's iMac
Install Homebrew formula via local privileged helper. No password requested.
```

Buttons:

- `Allow Once`
- `Deny`

Do not render `Allow Always` for privileged actions.

Unauthorized Discord clicks should be ephemeral and should not change approval state.

## Install and rollback runbook

The sudoers MVP install remains a manual, reviewed Phase 2B operation. Do not perform these steps from normal source tests.

Install plan:

- build/package the reviewed helper artifact
- copy it to `/usr/local/libexec/openclaw-privileged-helper`
- set root ownership and non-writable permissions on the helper artifact
- write `/Library/Application Support/OpenClaw/privileged-actions.json` with the pinned helper and brew paths
- create the request state directory with safe ownership and permissions
- add a sudoers entry for the exact helper path and exact OpenClaw invoking user only
- validate with `visudo -cf` before enabling
- run `openclaw-privileged-helper doctor --json`

Rollback plan:

- remove the sudoers entry and re-run `visudo -cf`
- remove the helper artifact from `/usr/local/libexec/openclaw-privileged-helper`
- remove or archive the OpenClaw privileged config and state directories
- confirm `doctor --json` reports the helper/sudoers paths as absent

Phase 2B pass 1 does not execute any install or rollback step.

## privileged doctor

`privileged doctor` is the local Phase 2B diagnostic. It must remain local-only and must not be exposed as a Discord-approved privileged action. It does not require Discord approval and does not perform network requests.

The helper MVP reports structured JSON checks for:

- helper binary exists and has expected ownership/permissions
- helper hash/version matches config
- config exists and is root-owned
- request directory exists and has safe permissions
- sudoers entry exists for the exact helper path
- configured Homebrew path exists and is executable

Doctor is implemented as source/tests in Phase 2B pass 1, but the helper is not installed by default yet.

## Manual Phase 2B acceptance gates

These checks require a live Discord approval surface and a helper-capable host, so they are not unit tests in Phase 2A:

- Unauthorized Discord button clicks are ephemeral and do not change approval state.
- `Allow Once` executes exactly one bound request once.
- `Deny` never reaches the helper.
- Replaying an already approved request is rejected.
- Normal cron/background `exec` continues without privileged-action approval prompts.
