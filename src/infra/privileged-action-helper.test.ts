import fs from "node:fs/promises";
import path from "node:path";

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { createTrackedTempDirs } from "../test-utils/tracked-temp-dirs.js";
import {
  buildPrivilegedActionBinding,
  buildPrivilegedActionDecisionBinding,
  buildPrivilegedActionRequest,
  type PrivilegedActionDecision,
} from "./privileged-actions.js";
import {
  consumePrivilegedActionRequestFile,
  parsePrivilegedHelperCliArgv,
  PRIVILEGED_HELPER_INSTALL_PATH,
  runPrivilegedHelperDoctor,
  validatePrivilegedHelperRequestRecord,
  type PrivilegedActionHelperRequestRecord,
  type PrivilegedHelperConfig,
} from "./privileged-action-helper.js";

const tempDirs = createTrackedTempDirs();
const nowMs = 1_000_000;

let requestStateDir = "";
let consumedStateDir = "";

beforeEach(async () => {
  const root = await tempDirs.make("openclaw-privileged-helper-");
  requestStateDir = path.join(root, "requests");
  consumedStateDir = path.join(root, "consumed");
  await fs.mkdir(requestStateDir, { recursive: true });
});

afterAll(async () => {
  await tempDirs.cleanup();
});

function config(overrides: Partial<PrivilegedHelperConfig> = {}): PrivilegedHelperConfig {
  return {
    helperPath: PRIVILEGED_HELPER_INSTALL_PATH,
    helperVersion: "0.1.0",
    helperHash: "sha256:helper",
    brewPath: "/opt/homebrew/bin/brew",
    requestStateDir,
    consumedStateDir,
    authorizedApprovers: ["195468996584275968"],
    ...overrides,
  };
}

function makeRecord(overrides: {
  id?: string;
  formula?: string;
  decision?: PrivilegedActionDecision;
  approverDiscordId?: string;
  createdAtMs?: number;
  expiresAtMs?: number;
  helperBrewPath?: "/usr/local/bin/brew" | "/opt/homebrew/bin/brew";
} = {}): PrivilegedActionHelperRequestRecord {
  const id = overrides.id ?? "req-1";
  const request = buildPrivilegedActionRequest({
    id,
    action: { verb: "homebrew.install", args: { formula: overrides.formula ?? "wget" } },
    target: { host: "node", nodeId: "mikes-imac" },
    helper: {
      path: PRIVILEGED_HELPER_INSTALL_PATH,
      version: "0.1.0",
      hash: "sha256:helper",
      brewPath: overrides.helperBrewPath ?? "/opt/homebrew/bin/brew",
    },
    agentId: "vladislava",
    sessionKey: "discord:channel:123",
    createdAtMs: overrides.createdAtMs ?? nowMs - 60_000,
    expiresAtMs: overrides.expiresAtMs ?? nowMs + 60_000,
  });
  expect(request.ok).toBe(true);
  if (!request.ok) {
    throw new Error(request.message);
  }
  return {
    request: request.value,
    binding: buildPrivilegedActionBinding(request.value),
    decision: buildPrivilegedActionDecisionBinding({
      request: request.value,
      decision: overrides.decision ?? "allow-once",
      decisionNonce: "nonce-1",
      approverDiscordId: overrides.approverDiscordId ?? "195468996584275968",
      approvedAtMs: nowMs - 30_000,
    }),
  };
}

async function writeRecordFile(record: PrivilegedActionHelperRequestRecord, mtimeMs = nowMs) {
  const file = path.join(requestStateDir, `${record.request.id}.json`);
  await fs.writeFile(file, JSON.stringify(record), { mode: 0o600 });
  const date = new Date(mtimeMs);
  await fs.utimes(file, date, date);
  return file;
}

describe("parsePrivilegedHelperCliArgv", () => {
  it("accepts only --request <id> and local doctor --json", () => {
    expect(parsePrivilegedHelperCliArgv(["--request", "req-1"])).toEqual({
      ok: true,
      value: { kind: "request", requestId: "req-1" },
    });
    expect(parsePrivilegedHelperCliArgv(["doctor", "--json"])).toEqual({
      ok: true,
      value: { kind: "doctor", json: true },
    });
  });

  it.each([
    { argv: [] },
    { argv: ["--request"] },
    { argv: ["--request", "req-1", "wget"] },
    { argv: ["homebrew.install", "wget"] },
    { argv: ["doctor"] },
    { argv: ["doctor", "--text"] },
    { argv: ["--request", "../req-1"] },
    { argv: ["--request", ".."] },
    { argv: ["--request", "."] },
    { argv: ["--request", "req 1"] },
  ])("rejects argv shape $argv", ({ argv }) => {
    expect(parsePrivilegedHelperCliArgv(argv).ok).toBe(false);
  });
});

describe("validatePrivilegedHelperRequestRecord", () => {
  it("reconstructs the helper-side binding and creates a shell-free pinned brew plan", () => {
    const result = validatePrivilegedHelperRequestRecord({
      config: config(),
      record: makeRecord({ formula: "openssl@3" }),
      nowMs,
      mtimeMs: nowMs - 10_000,
    });

    expect(result).toEqual({
      ok: true,
      value: {
        requestId: "req-1",
        executable: "/opt/homebrew/bin/brew",
        argv: ["install", "openssl@3"],
        shell: false,
      },
    });
  });

  it("rejects arbitrary or PATH-derived brew paths", () => {
    const result = validatePrivilegedHelperRequestRecord({
      config: { ...config(), brewPath: "brew" as "/opt/homebrew/bin/brew" },
      record: makeRecord(),
      nowMs,
      mtimeMs: nowMs,
    });

    expect(result).toMatchObject({ ok: false, code: "BREW_PATH_UNSUPPORTED" });
  });

  it("rejects helper-side brew path binding mismatches", () => {
    const result = validatePrivilegedHelperRequestRecord({
      config: config({ brewPath: "/usr/local/bin/brew" }),
      record: makeRecord({ helperBrewPath: "/opt/homebrew/bin/brew" }),
      nowMs,
      mtimeMs: nowMs,
    });

    expect(result).toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_BREW_PATH_MISMATCH" });
  });

  it("rejects expired, replayed, unauthorized, and mismatched approval records", () => {
    expect(
      validatePrivilegedHelperRequestRecord({
        config: config(),
        record: makeRecord({ expiresAtMs: nowMs - 1 }),
        nowMs,
        mtimeMs: nowMs - 10_000,
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_ACTION_EXPIRED" });

    expect(
      validatePrivilegedHelperRequestRecord({
        config: config(),
        record: makeRecord(),
        nowMs,
        mtimeMs: nowMs,
        consumedRequestIds: new Set(["req-1"]),
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_ACTION_REPLAY" });

    expect(
      validatePrivilegedHelperRequestRecord({
        config: config(),
        record: makeRecord({ approverDiscordId: "not-authorized" }),
        nowMs,
        mtimeMs: nowMs,
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_ACTION_UNAUTHORIZED_APPROVER" });

    const tampered = makeRecord();
    tampered.binding = { ...tampered.binding, bindingHash: "sha256:changed" };
    expect(
      validatePrivilegedHelperRequestRecord({
        config: config(),
        record: tampered,
        nowMs,
        mtimeMs: nowMs,
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_ACTION_BINDING_MISMATCH" });
  });

  it("rejects stale, pre-window, and future request mtimes", () => {
    expect(
      validatePrivilegedHelperRequestRecord({
        config: config(),
        record: makeRecord(),
        nowMs,
        mtimeMs: nowMs - 301_000,
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_STALE_MTIME" });

    expect(
      validatePrivilegedHelperRequestRecord({
        config: config(),
        record: makeRecord({ createdAtMs: nowMs + 60_000, expiresAtMs: nowMs + 120_000 }),
        nowMs,
        mtimeMs: nowMs,
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_STALE_MTIME" });

    expect(
      validatePrivilegedHelperRequestRecord({
        config: config(),
        record: makeRecord(),
        nowMs,
        mtimeMs: nowMs + 31_000,
      }),
    ).toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_FUTURE_MTIME" });
  });
});

describe("consumePrivilegedActionRequestFile", () => {
  it("validates and atomically consumes a request before returning an execution plan", async () => {
    const record = makeRecord({ id: "req-consume" });
    const file = await writeRecordFile(record, nowMs - 10_000);
    const consumed = path.join(consumedStateDir, "req-consume.json");

    const result = await consumePrivilegedActionRequestFile({
      config: config(),
      requestId: "req-consume",
      nowMs,
    });

    expect(result).toMatchObject({ ok: true, value: { requestId: "req-consume" } });
    await expect(fs.stat(file)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(fs.stat(consumed)).resolves.toBeTruthy();
  });

  it("reports replay when only the consumed file remains", async () => {
    const record = makeRecord({ id: "req-replay" });
    await fs.mkdir(consumedStateDir, { recursive: true });
    await fs.writeFile(path.join(consumedStateDir, "req-replay.json"), JSON.stringify(record), {
      mode: 0o600,
    });

    await expect(
      consumePrivilegedActionRequestFile({ config: config(), requestId: "req-replay", nowMs }),
    ).resolves.toMatchObject({ ok: false, code: "PRIVILEGED_ACTION_REPLAY" });
  });

  it("rejects symlink request files", async () => {
    const target = path.join(requestStateDir, "real.json");
    await fs.writeFile(target, JSON.stringify(makeRecord({ id: "req-link" })), { mode: 0o600 });
    await fs.symlink(target, path.join(requestStateDir, "req-link.json"));

    await expect(
      consumePrivilegedActionRequestFile({ config: config(), requestId: "req-link", nowMs }),
    ).resolves.toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_REQUEST_SYMLINK" });
  });

  it("rejects group/world writable files and malformed JSON", async () => {
    const writable = await writeRecordFile(makeRecord({ id: "req-writable" }));
    await fs.chmod(writable, 0o660);
    await expect(
      consumePrivilegedActionRequestFile({ config: config(), requestId: "req-writable", nowMs }),
    ).resolves.toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_REQUEST_WRITABLE" });

    const malformed = path.join(requestStateDir, "req-malformed.json");
    await fs.writeFile(malformed, "{", { mode: 0o600 });
    await expect(
      consumePrivilegedActionRequestFile({ config: config(), requestId: "req-malformed", nowMs }),
    ).resolves.toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_MALFORMED_JSON" });
  });
});

describe("runPrivilegedHelperDoctor", () => {
  it("returns structured local checks without requiring a Discord approval", async () => {
    const fakeFs = {
      lstat: fs.lstat,
      readFile: fs.readFile,
      rename: fs.rename,
      mkdir: fs.mkdir,
      async access() {
        return undefined;
      },
    };

    const report = await runPrivilegedHelperDoctor({
      config: config({
        configPath: "/Library/Application Support/OpenClaw/privileged-actions.json",
        sudoersPath: "/etc/sudoers.d/openclaw-privileged-helper",
      }),
      fs: fakeFs,
    });

    expect(report.ok).toBe(true);
    expect(report.helperSource).toBe("src/infra/privileged-action-helper.ts");
    expect(report.checks.map((check) => check.name)).toEqual([
      "helper",
      "config",
      "state",
      "brew",
      "sudoers",
    ]);
    expect(JSON.stringify(report)).not.toContain("approval");
  });
});
