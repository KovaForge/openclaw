import { describe, expect, it } from "vitest";
import { validateConfigObjectRaw } from "./validation.js";

describe("privilegedActions config", () => {
  it("accepts the Gatekeeper MVP config without global exec policy", () => {
    const result = validateConfigObjectRaw({
      privilegedActions: {
        enabled: true,
        approval: {
          target: "dm",
          approvers: ["195468996584275968"],
          agentFilter: ["vladislava"],
          sessionFilter: ["discord:"],
        },
        helper: {
          mode: "sudoers",
          path: "/usr/local/libexec/openclaw-privileged-helper",
          brewPath: "/opt/homebrew/bin/brew",
          configPath: "/Library/Application Support/OpenClaw/privileged-actions.json",
        },
        verbs: {
          homebrew: {
            install: { enabled: true, formulaAllowlist: ["wget"] },
          },
        },
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.config.tools?.exec).toBeUndefined();
    expect(result.config.privilegedActions?.helper?.brewPath).toBe("/opt/homebrew/bin/brew");
  });

  it("rejects arbitrary helper brew paths", () => {
    const result = validateConfigObjectRaw({
      privilegedActions: {
        helper: {
          brewPath: "/usr/bin/env brew",
        },
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.some((issue) => issue.path === "privilegedActions.helper.brewPath"))
        .toBe(true);
    }
  });

  it("schema-enforces that password prompts cannot be enabled", () => {
    const result = validateConfigObjectRaw({
      privilegedActions: {
        passwordPrompt: true,
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.some((issue) => issue.path === "privilegedActions.passwordPrompt"))
        .toBe(true);
    }
  });

  it("rejects non-DM privileged approval targets for the MVP", () => {
    const result = validateConfigObjectRaw({
      privilegedActions: {
        approval: { target: "channel" },
      },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.some((issue) => issue.path === "privilegedActions.approval.target"))
        .toBe(true);
    }
  });

  it("keeps the privileged action namespace orthogonal to cron-safe exec settings", () => {
    const result = validateConfigObjectRaw({
      tools: {
        exec: {
          security: "full",
          ask: "off",
        },
      },
      privilegedActions: {
        enabled: true,
        approval: { target: "dm" },
      },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.config.tools?.exec?.security).toBe("full");
    expect(result.config.tools?.exec?.ask).toBe("off");
  });
});
