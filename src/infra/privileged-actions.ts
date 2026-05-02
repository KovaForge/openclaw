import crypto from "node:crypto";

export const PRIVILEGED_ACTION_APPROVAL_TARGET = "dm" as const;
export const PRIVILEGED_ACTION_PASSWORD_PROMPT = false as const;
export const PRIVILEGED_ACTION_ALLOWED_DECISIONS = ["allow-once", "deny"] as const;
export const PRIVILEGED_ACTION_DEFAULT_EXPIRY_MS = 10 * 60 * 1000;
// `privileged doctor` is a local Phase 2B diagnostic boundary, not a Discord-approved action.
export const PRIVILEGED_ACTION_DOCTOR_PHASE = "phase-2b-design-only" as const;
export const PRIVILEGED_ACTION_KNOWN_BREW_PATHS = [
  "/usr/local/bin/brew",
  "/opt/homebrew/bin/brew",
] as const;

export type PrivilegedActionVerb = "homebrew.install";
export type PrivilegedActionDecision = (typeof PRIVILEGED_ACTION_ALLOWED_DECISIONS)[number];
export type PrivilegedActionBrewPath = (typeof PRIVILEGED_ACTION_KNOWN_BREW_PATHS)[number];

export type HomebrewInstallAction = {
  verb: "homebrew.install";
  args: {
    formula: string;
  };
};

export type PrivilegedAction = HomebrewInstallAction;

export type PrivilegedActionTarget = {
  host: "gateway" | "node";
  nodeId?: string | null;
};

export type PrivilegedActionHelperIdentity = {
  path: string;
  version?: string | null;
  hash?: string | null;
};

export type PrivilegedActionRequest = {
  id: string;
  action: PrivilegedAction;
  target: PrivilegedActionTarget;
  helper: PrivilegedActionHelperIdentity;
  agentId?: string | null;
  sessionKeyHash?: string | null;
  createdAtMs: number;
  expiresAtMs: number;
  passwordPrompt: false;
  approvalTarget: "dm";
  allowedDecisions: readonly PrivilegedActionDecision[];
};

export type PrivilegedActionBinding = {
  requestId: string;
  verb: PrivilegedActionVerb;
  normalizedArgs: PrivilegedAction["args"];
  target: PrivilegedActionTarget;
  helper: PrivilegedActionHelperIdentity;
  agentId: string | null;
  sessionKeyHash: string | null;
  expiresAtMs: number;
  bindingHash: string;
};

export type PrivilegedActionDecisionBinding = {
  requestId: string;
  decision: PrivilegedActionDecision;
  decisionNonce: string;
  approverDiscordId: string;
  approvedAtMs: number;
  bindingHash: string;
};

export type PrivilegedActionResolved = {
  id: string;
  decision: PrivilegedActionDecision;
  resolvedByDiscordId?: string | null;
  ts: number;
  request?: PrivilegedActionRequest;
};

export type PrivilegedActionValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: string; message: string };

export type PrivilegedActionExecutionCheck =
  | { ok: true }
  | { ok: false; code: string; message: string };

const HOMEBREW_FORMULA_PATTERN = /^[a-zA-Z0-9@._+-]+$/;
const MAX_HOMEBREW_FORMULA_LENGTH = 128;

function fail(code: string, message: string): PrivilegedActionValidationResult<never> {
  return { ok: false, code, message };
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(",")}}`;
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function hashPrivilegedActionSessionKey(sessionKey?: string | null): string | null {
  const normalized = sessionKey?.trim() ?? "";
  return normalized ? sha256(normalized) : null;
}

export function normalizeHomebrewFormula(
  value: unknown,
): PrivilegedActionValidationResult<string> {
  if (typeof value !== "string") {
    return fail("FORMULA_NOT_STRING", "Homebrew formula must be a string.");
  }
  if (value.length === 0) {
    return fail("FORMULA_EMPTY", "Homebrew formula cannot be empty.");
  }
  if (value.length > MAX_HOMEBREW_FORMULA_LENGTH) {
    return fail("FORMULA_TOO_LONG", "Homebrew formula is longer than 128 characters.");
  }
  if (value === "." || value === "..") {
    return fail("FORMULA_DOT_PATH", "Homebrew formula cannot be . or ...");
  }
  if (value.includes("/") || value.includes("\\")) {
    return fail("FORMULA_PATH_SEPARATOR", "Homebrew formula cannot contain path separators.");
  }
  if (!/^[\x21-\x7e]+$/.test(value)) {
    return fail(
      "FORMULA_NON_ASCII_OR_CONTROL",
      "Homebrew formula must be printable ASCII with no whitespace or control characters.",
    );
  }
  if (value.startsWith("-")) {
    return fail("FORMULA_FLAG", "Homebrew formula cannot start with a flag marker.");
  }
  if (!HOMEBREW_FORMULA_PATTERN.test(value)) {
    return fail(
      "FORMULA_INVALID_CHARS",
      "Homebrew formula may contain only letters, digits, @, ., _, +, and -.",
    );
  }
  return { ok: true, value };
}

export function normalizePrivilegedActionBrewPath(
  value: unknown,
): PrivilegedActionValidationResult<PrivilegedActionBrewPath> {
  if (typeof value !== "string") {
    return fail("BREW_PATH_NOT_STRING", "Homebrew path must be a string.");
  }
  if ((PRIVILEGED_ACTION_KNOWN_BREW_PATHS as readonly string[]).includes(value)) {
    return { ok: true, value: value as PrivilegedActionBrewPath };
  }
  return fail(
    "BREW_PATH_UNSUPPORTED",
    "Homebrew path must be pinned to /usr/local/bin/brew or /opt/homebrew/bin/brew.",
  );
}

export function normalizePrivilegedAction(
  value: unknown,
): PrivilegedActionValidationResult<PrivilegedAction> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return fail("ACTION_NOT_OBJECT", "Privileged action must be an object.");
  }
  const candidate = value as { verb?: unknown; args?: { formula?: unknown } };
  if (candidate.verb !== "homebrew.install") {
    return fail("ACTION_UNSUPPORTED_VERB", "Only homebrew.install is supported in the MVP.");
  }
  const formula = normalizeHomebrewFormula(candidate.args?.formula);
  if (!formula.ok) {
    return formula;
  }
  return {
    ok: true,
    value: {
      verb: "homebrew.install",
      args: { formula: formula.value },
    },
  };
}

export function formatPrivilegedActionCanonicalDisplay(action: PrivilegedAction): string {
  return `${action.verb}  |  ${action.args.formula}`;
}

export function buildPrivilegedActionRequest(params: {
  id: string;
  action: unknown;
  target: PrivilegedActionTarget;
  helper: PrivilegedActionHelperIdentity;
  agentId?: string | null;
  sessionKey?: string | null;
  createdAtMs: number;
  expiresAtMs?: number;
}): PrivilegedActionValidationResult<PrivilegedActionRequest> {
  const action = normalizePrivilegedAction(params.action);
  if (!action.ok) {
    return action;
  }
  return {
    ok: true,
    value: {
      id: params.id,
      action: action.value,
      target: params.target,
      helper: params.helper,
      agentId: params.agentId ?? null,
      sessionKeyHash: hashPrivilegedActionSessionKey(params.sessionKey),
      createdAtMs: params.createdAtMs,
      expiresAtMs: params.expiresAtMs ?? params.createdAtMs + PRIVILEGED_ACTION_DEFAULT_EXPIRY_MS,
      passwordPrompt: PRIVILEGED_ACTION_PASSWORD_PROMPT,
      approvalTarget: PRIVILEGED_ACTION_APPROVAL_TARGET,
      allowedDecisions: PRIVILEGED_ACTION_ALLOWED_DECISIONS,
    },
  };
}

export function buildPrivilegedActionBinding(
  request: PrivilegedActionRequest,
): PrivilegedActionBinding {
  const withoutHash = {
    requestId: request.id,
    verb: request.action.verb,
    normalizedArgs: request.action.args,
    target: request.target,
    helper: request.helper,
    agentId: request.agentId ?? null,
    sessionKeyHash: request.sessionKeyHash ?? null,
    expiresAtMs: request.expiresAtMs,
  };
  return {
    ...withoutHash,
    bindingHash: sha256(stableJson(withoutHash)),
  };
}

export function buildPrivilegedActionDecisionBinding(params: {
  request: PrivilegedActionRequest;
  decision: PrivilegedActionDecision;
  decisionNonce: string;
  approverDiscordId: string;
  approvedAtMs: number;
}): PrivilegedActionDecisionBinding {
  const binding = buildPrivilegedActionBinding(params.request);
  return {
    requestId: params.request.id,
    decision: params.decision,
    decisionNonce: params.decisionNonce,
    approverDiscordId: params.approverDiscordId,
    approvedAtMs: params.approvedAtMs,
    bindingHash: binding.bindingHash,
  };
}

export function verifyPrivilegedActionExecution(params: {
  expected: PrivilegedActionBinding;
  actual: PrivilegedActionBinding;
  decision: PrivilegedActionDecisionBinding | null;
  nowMs: number;
  authorizedApprovers: ReadonlySet<string>;
  consumedRequestIds?: ReadonlySet<string>;
}): PrivilegedActionExecutionCheck {
  if (params.nowMs > params.expected.expiresAtMs) {
    return { ok: false, code: "PRIVILEGED_ACTION_EXPIRED", message: "privileged action expired" };
  }
  if (params.consumedRequestIds?.has(params.expected.requestId)) {
    return {
      ok: false,
      code: "PRIVILEGED_ACTION_REPLAY",
      message: "privileged action already consumed",
    };
  }
  if (!params.decision) {
    return {
      ok: false,
      code: "PRIVILEGED_ACTION_DECISION_MISSING",
      message: "privileged action decision missing",
    };
  }
  if (params.decision.decision !== "allow-once") {
    return {
      ok: false,
      code: "PRIVILEGED_ACTION_NOT_ALLOWED",
      message: "privileged action was not allowed once",
    };
  }
  if (!params.authorizedApprovers.has(params.decision.approverDiscordId)) {
    return {
      ok: false,
      code: "PRIVILEGED_ACTION_UNAUTHORIZED_APPROVER",
      message: "privileged action approver is not authorized",
    };
  }
  if (
    params.expected.bindingHash !== params.actual.bindingHash ||
    params.expected.bindingHash !== params.decision.bindingHash ||
    params.expected.requestId !== params.decision.requestId
  ) {
    return {
      ok: false,
      code: "PRIVILEGED_ACTION_BINDING_MISMATCH",
      message: "privileged action approval does not match execution request",
    };
  }
  return { ok: true };
}
