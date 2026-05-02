import { describe, expect, it } from "vitest";
import {
  buildPrivilegedActionBinding,
  buildPrivilegedActionDecisionBinding,
  buildPrivilegedActionRequest,
  formatPrivilegedActionCanonicalDisplay,
  normalizeHomebrewFormula,
  normalizePrivilegedActionBrewPath,
  PRIVILEGED_ACTION_DOCTOR_PHASE,
  verifyPrivilegedActionExecution,
} from "./privileged-actions.js";

const baseParams = {
  id: "req-1",
  action: { verb: "homebrew.install", args: { formula: "wget" } },
  target: { host: "node" as const, nodeId: "mikes-imac" },
  helper: {
    path: "/usr/local/libexec/openclaw-privileged-helper",
    version: "0.1.0",
    hash: "sha256:helper",
  },
  agentId: "vladislava",
  sessionKey: "discord:channel:123",
  createdAtMs: 1_000,
  expiresAtMs: 11_000,
};

function makeRequest(overrides: Partial<typeof baseParams> = {}) {
  const result = buildPrivilegedActionRequest({ ...baseParams, ...overrides });
  expect(result.ok).toBe(true);
  if (!result.ok) {
    throw new Error(result.message);
  }
  return result.value;
}

describe("normalizeHomebrewFormula", () => {
  it.each(["wget", "openssl@3", "node@20", "foo_bar", "foo-bar", "foo.bar", "foo+bar"])(
    "accepts %s",
    (formula) => {
      expect(normalizeHomebrewFormula(formula)).toEqual({ ok: true, value: formula });
    },
  );

  it.each([
    "",
    ".",
    "..",
    "foo/bar",
    "foo\\bar",
    "foo bar",
    "--formula",
    "$(whoami)",
    "`whoami`",
    "foo;bar",
    "foo|bar",
    "foo&bar",
    "cafe\u0301",
    "caf\u00e9",
    "foo\nbar",
    "foo\u0000bar",
  ])("rejects %s", (formula) => {
    expect(normalizeHomebrewFormula(formula).ok).toBe(false);
  });

  it("rejects formulas over 128 characters", () => {
    expect(normalizeHomebrewFormula("a".repeat(129)).ok).toBe(false);
  });
});

describe("normalizePrivilegedActionBrewPath", () => {
  it.each(["/usr/local/bin/brew", "/opt/homebrew/bin/brew"])("accepts %s", (brewPath) => {
    expect(normalizePrivilegedActionBrewPath(brewPath)).toEqual({ ok: true, value: brewPath });
  });

  it.each(["brew", "/bin/brew", "/usr/bin/env brew", "/tmp/brew", "", null])(
    "rejects %s",
    (brewPath) => {
      expect(normalizePrivilegedActionBrewPath(brewPath).ok).toBe(false);
    },
  );
});

describe("privileged action binding", () => {
  it("builds canonical display from the normalized bound action", () => {
    const request = makeRequest({
      action: { verb: "homebrew.install", args: { formula: "openssl@3" } },
    });

    expect(formatPrivilegedActionCanonicalDisplay(request.action)).toBe(
      "homebrew.install  |  openssl@3",
    );
    expect(request.passwordPrompt).toBe(false);
    expect(request.approvalTarget).toBe("dm");
    expect(request.allowedDecisions).toEqual(["allow-once", "deny"]);
    expect(PRIVILEGED_ACTION_DOCTOR_PHASE).toBe("phase-2b-design-only");
  });

  it("accepts a matching allow-once decision", () => {
    const request = makeRequest();
    const binding = buildPrivilegedActionBinding(request);
    const decision = buildPrivilegedActionDecisionBinding({
      request,
      decision: "allow-once",
      decisionNonce: "nonce-1",
      approverDiscordId: "195468996584275968",
      approvedAtMs: 2_000,
    });

    expect(
      verifyPrivilegedActionExecution({
        expected: binding,
        actual: binding,
        decision,
        nowMs: 3_000,
        authorizedApprovers: new Set(["195468996584275968"]),
      }),
    ).toEqual({ ok: true });
  });

  it.each([
    ["args", { action: { verb: "homebrew.install", args: { formula: "curl" } } }],
    ["host", { target: { host: "gateway" as const } }],
    ["agent", { agentId: "mikhail" }],
    ["session", { sessionKey: "discord:channel:other" }],
    ["helper", { helper: { ...baseParams.helper, hash: "sha256:changed" } }],
  ])("rejects mismatched %s binding", (_name, override) => {
    const request = makeRequest();
    const expected = buildPrivilegedActionBinding(request);
    const changed = buildPrivilegedActionRequest({ ...baseParams, ...override });
    expect(changed.ok).toBe(true);
    if (!changed.ok) {
      return;
    }
    const actual = buildPrivilegedActionBinding(changed.value);
    const decision = buildPrivilegedActionDecisionBinding({
      request,
      decision: "allow-once",
      decisionNonce: "nonce-1",
      approverDiscordId: "195468996584275968",
      approvedAtMs: 2_000,
    });

    expect(
      verifyPrivilegedActionExecution({
        expected,
        actual,
        decision,
        nowMs: 3_000,
        authorizedApprovers: new Set(["195468996584275968"]),
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_ACTION_BINDING_MISMATCH" });
  });

  it("rejects unsupported verbs during request normalization", () => {
    expect(
      buildPrivilegedActionRequest({
        ...baseParams,
        action: { verb: "homebrew.update", args: { formula: "wget" } },
      }).ok,
    ).toBe(false);
  });

  it("rejects unauthorized approvers", () => {
    const request = makeRequest();
    const binding = buildPrivilegedActionBinding(request);
    const decision = buildPrivilegedActionDecisionBinding({
      request,
      decision: "allow-once",
      decisionNonce: "nonce-1",
      approverDiscordId: "not-authorized",
      approvedAtMs: 2_000,
    });

    expect(
      verifyPrivilegedActionExecution({
        expected: binding,
        actual: binding,
        decision,
        nowMs: 3_000,
        authorizedApprovers: new Set(["195468996584275968"]),
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_ACTION_UNAUTHORIZED_APPROVER" });
  });

  it("rejects replayed requests", () => {
    const request = makeRequest();
    const binding = buildPrivilegedActionBinding(request);
    const decision = buildPrivilegedActionDecisionBinding({
      request,
      decision: "allow-once",
      decisionNonce: "nonce-1",
      approverDiscordId: "195468996584275968",
      approvedAtMs: 2_000,
    });

    expect(
      verifyPrivilegedActionExecution({
        expected: binding,
        actual: binding,
        decision,
        nowMs: 3_000,
        authorizedApprovers: new Set(["195468996584275968"]),
        consumedRequestIds: new Set([request.id]),
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_ACTION_REPLAY" });
  });

  it("rejects expired requests", () => {
    const request = makeRequest();
    const binding = buildPrivilegedActionBinding(request);
    const decision = buildPrivilegedActionDecisionBinding({
      request,
      decision: "allow-once",
      decisionNonce: "nonce-1",
      approverDiscordId: "195468996584275968",
      approvedAtMs: 2_000,
    });

    expect(
      verifyPrivilegedActionExecution({
        expected: binding,
        actual: binding,
        decision,
        nowMs: 12_000,
        authorizedApprovers: new Set(["195468996584275968"]),
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_ACTION_EXPIRED" });
  });
});
