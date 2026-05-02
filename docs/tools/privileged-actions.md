---
summary: "Gatekeeper privileged actions: Discord-mediated approvals for narrow local helper verbs"
read_when:
  - Designing or configuring privileged actions
  - Reviewing Gatekeeper approval security
  - Diagnosing privileged action helper setup
title: "Privileged actions"
---

Privileged actions are the Gatekeeper approval path for narrow local helper verbs. They are separate from normal `exec` and from `~/.openclaw/exec-approvals.json`.

The MVP supports design/types/tests for one mutating verb:

- `homebrew.install(formula)`

It also documents the planned local diagnostic command:

- `privileged doctor`

No helper, sudoers entry, or launchd service is installed by this phase.

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

## privileged doctor

`privileged doctor` is the planned local Phase 2B diagnostic. It is design-only in Phase 2A, must remain local-only, and must not be exposed as a Discord-approved privileged action. It does not require Discord approval and does not perform network requests.

The helper MVP should report structured checks for:

- helper binary exists and has expected ownership/permissions
- helper hash/version matches config
- config exists and is root-owned
- request directory exists and has safe permissions
- sudoers entry exists for the exact helper path
- configured Homebrew path exists and is executable

Doctor is documentation/design-only in Phase 2A.

## Manual Phase 2B acceptance gates

These checks require a live Discord approval surface and a helper-capable host, so they are not unit tests in Phase 2A:

- Unauthorized Discord button clicks are ephemeral and do not change approval state.
- `Allow Once` executes exactly one bound request once.
- `Deny` never reaches the helper.
- Replaying an already approved request is rejected.
- Normal cron/background `exec` continues without privileged-action approval prompts.
