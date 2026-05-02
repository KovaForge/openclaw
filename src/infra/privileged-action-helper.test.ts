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
  executePrivilegedHelperPlan,
  loadPrivilegedHelperConfigFile,
  parsePrivilegedHelperCliArgv,
  PRIVILEGED_HELPER_DEFAULT_CONFIG_PATH,
  PRIVILEGED_HELPER_INSTALL_PATH,
  runPrivilegedHelperCliCommand,
  runPrivilegedHelperDoctor,
  validatePrivilegedHelperRequestRecord,
  type PrivilegedActionHelperRequestRecord,
  type PrivilegedHelperConfig,
  type PrivilegedHelperDoctorCheck,
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

function fakeStat(params: {
  file?: boolean;
  directory?: boolean;
  mode?: number;
  uid?: number;
  gid?: number;
} = {}) {
  return {
    isSymbolicLink: () => false,
    isFile: () => params.file ?? !params.directory,
    isDirectory: () => params.directory ?? false,
    mode: params.mode ?? 0o100755,
    mtimeMs: nowMs,
    uid: params.uid ?? 0,
    gid: params.gid ?? 0,
  };
}

function makeDoctorFs(overrides: {
  sudoersContent?: string;
  stats?: Record<string, ReturnType<typeof fakeStat>>;
} = {}) {
  const sudoersPath = "/etc/sudoers.d/openclaw-privileged-helper";
  const configPath = "/Library/Application Support/OpenClaw/privileged-actions.json";
  const stats = {
    [PRIVILEGED_HELPER_INSTALL_PATH]: fakeStat({ mode: 0o100755 }),
    [configPath]: fakeStat({ mode: 0o100644 }),
    [requestStateDir]: fakeStat({ directory: true, mode: 0o40750 }),
    ["/opt/homebrew/bin/brew"]: fakeStat({ mode: 0o100755 }),
    [sudoersPath]: fakeStat({ mode: 0o100440 }),
    ...overrides.stats,
  };
  return {
    lstat: async (filePath: string) => {
      const stat = stats[filePath];
      if (!stat) {
        throw Object.assign(new Error("missing"), { code: "ENOENT" });
      }
      return stat;
    },
    readFile: async (filePath: string) => {
      if (filePath === sudoersPath) {
        return (
          overrides.sudoersContent ??
          `mike ALL = (root) NOPASSWD: ${PRIVILEGED_HELPER_INSTALL_PATH}\n`
        );
      }
      return "{}";
    },
    rename: fs.rename,
    mkdir: fs.mkdir,
    async access(filePath: string) {
      if (!stats[filePath]) {
        throw Object.assign(new Error("missing"), { code: "ENOENT" });
      }
    },
  };
}

function doctorConfig(overrides: Partial<PrivilegedHelperConfig> = {}) {
  return config({
    configPath: "/Library/Application Support/OpenClaw/privileged-actions.json",
    sudoersPath: "/etc/sudoers.d/openclaw-privileged-helper",
    sudoersUser: "mike",
    ...overrides,
  });
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
        env: {
          HOME: "/var/empty",
          LOGNAME: "root",
          SHELL: "/bin/sh",
          USER: "root",
        },
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

  it("rejects group/world writable files, owner mismatches, and malformed JSON", async () => {
    const writable = await writeRecordFile(makeRecord({ id: "req-writable" }));
    await fs.chmod(writable, 0o660);
    await expect(
      consumePrivilegedActionRequestFile({ config: config(), requestId: "req-writable", nowMs }),
    ).resolves.toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_REQUEST_WRITABLE" });

    const ownerMismatchRecord = makeRecord({ id: "req-owner" });
    const ownerMismatchPath = path.join(requestStateDir, "req-owner.json");
    const ownerMismatchFs = {
      lstat: async () => fakeStat({ mode: 0o100600, uid: 501, gid: 20 }),
      readFile: async () => JSON.stringify(ownerMismatchRecord),
      rename: fs.rename,
      mkdir: fs.mkdir,
      access: fs.access,
    };
    await expect(
      consumePrivilegedActionRequestFile({
        config: config({ expectedOwnerUid: 0, expectedGroupGid: 0 }),
        requestId: "req-owner",
        nowMs,
        fs: ownerMismatchFs,
      }),
    ).resolves.toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_REQUEST_OWNER" });
    expect(ownerMismatchPath).toContain("req-owner.json");

    const malformed = path.join(requestStateDir, "req-malformed.json");
    await fs.writeFile(malformed, "{", { mode: 0o600 });
    await expect(
      consumePrivilegedActionRequestFile({ config: config(), requestId: "req-malformed", nowMs }),
    ).resolves.toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_MALFORMED_JSON" });
  });
});

describe("loadPrivilegedHelperConfigFile", () => {
  it("loads trusted local helper config from JSON", async () => {
    const configPath = path.join(requestStateDir, "privileged-actions.json");
    await fs.writeFile(
      configPath,
      JSON.stringify({
        helperPath: PRIVILEGED_HELPER_INSTALL_PATH,
        helperVersion: "0.1.0",
        helperHash: "sha256:helper",
        brewPath: "/opt/homebrew/bin/brew",
        requestStateDir,
        consumedStateDir,
        authorizedApprovers: ["195468996584275968"],
        sudoersPath: "/etc/sudoers.d/openclaw-privileged-helper",
      }),
      { mode: 0o600 },
    );

    await expect(loadPrivilegedHelperConfigFile({ configPath })).resolves.toMatchObject({
      ok: true,
      value: {
        helperPath: PRIVILEGED_HELPER_INSTALL_PATH,
        configPath,
        brewPath: "/opt/homebrew/bin/brew",
        authorizedApprovers: ["195468996584275968"],
      },
    });
  });

  it("rejects missing config and unsupported helper config values", async () => {
    await expect(
      loadPrivilegedHelperConfigFile({ configPath: PRIVILEGED_HELPER_DEFAULT_CONFIG_PATH }),
    ).resolves.toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_CONFIG_MALFORMED" });

    const configPath = path.join(requestStateDir, "bad.json");
    await fs.writeFile(
      configPath,
      JSON.stringify({
        helperPath: "/tmp/helper",
        brewPath: "brew",
        requestStateDir,
        authorizedApprovers: [],
      }),
    );
    await expect(loadPrivilegedHelperConfigFile({ configPath })).resolves.toMatchObject({
      ok: false,
    });
  });
});

describe("executePrivilegedHelperPlan", () => {
  it("spawns the pinned brew executable without shell or PATH", async () => {
    const plan = validatePrivilegedHelperRequestRecord({
      config: config(),
      record: makeRecord({ formula: "wget" }),
      nowMs,
      mtimeMs: nowMs,
    });
    expect(plan.ok).toBe(true);
    if (!plan.ok) {
      throw new Error(plan.message);
    }
    const calls: unknown[] = [];
    const result = await executePrivilegedHelperPlan({
      plan: plan.value,
      spawn: async (executable, argv, options) => {
        calls.push({ executable, argv, options });
        return { code: 0, signal: null, stdout: "", stderr: "" };
      },
    });

    expect(result.code).toBe(0);
    expect(calls).toEqual([
      {
        executable: "/opt/homebrew/bin/brew",
        argv: ["install", "wget"],
        options: {
          shell: false,
          env: {
            HOME: "/var/empty",
            LOGNAME: "root",
            SHELL: "/bin/sh",
            USER: "root",
          },
        },
      },
    ]);
    expect(JSON.stringify(calls)).not.toContain("PATH");
  });
});

describe("runPrivilegedHelperCliCommand", () => {
  it("runs doctor locally and executes request records through the injected spawn boundary", async () => {
    const doctor = await runPrivilegedHelperCliCommand({
      argv: ["doctor", "--json"],
      config: doctorConfig(),
      fs: makeDoctorFs(),
    });
    expect(doctor).toMatchObject({ ok: true, kind: "doctor" });

    await writeRecordFile(makeRecord({ id: "req-cli" }), nowMs);
    const request = await runPrivilegedHelperCliCommand({
      argv: ["--request", "req-cli"],
      config: config(),
      nowMs,
      spawn: async () => ({ code: 0, signal: null, stdout: "", stderr: "" }),
    });
    expect(request).toMatchObject({ ok: true, kind: "request" });
  });

  it("reports brew failure without making the request reusable", async () => {
    await writeRecordFile(makeRecord({ id: "req-brew-fail" }), nowMs);
    const result = await runPrivilegedHelperCliCommand({
      argv: ["--request", "req-brew-fail"],
      config: config(),
      nowMs,
      spawn: async () => ({ code: 2, signal: null, stdout: "", stderr: "TOKEN=secret" }),
    });
    expect(result).toMatchObject({ ok: false, code: "PRIVILEGED_HELPER_BREW_FAILED" });
    await expect(fs.stat(path.join(consumedStateDir, "req-brew-fail.json"))).resolves.toBeTruthy();
  });
});

describe("runPrivilegedHelperDoctor", () => {
  it("returns structured local checks without requiring a Discord approval", async () => {
    const visudoCalls: Array<{ sudoersPath: string; expectedEntry: string }> = [];
    const report = await runPrivilegedHelperDoctor({
      config: doctorConfig(),
      fs: makeDoctorFs(),
      visudo: async (params): Promise<PrivilegedHelperDoctorCheck> => {
        visudoCalls.push(params);
        return {
          name: "sudoers",
          status: "pass",
          path: params.sudoersPath,
          message: "visudo -cf ok",
        };
      },
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
    expect(report.checks.find((check) => check.name === "sudoers")).toMatchObject({
      status: "pass",
      message: "exact entry and validation ok",
    });
    expect(visudoCalls).toEqual([
      {
        sudoersPath: "/etc/sudoers.d/openclaw-privileged-helper",
        expectedEntry: `mike ALL = (root) NOPASSWD: ${PRIVILEGED_HELPER_INSTALL_PATH}`,
      },
    ]);
    expect(JSON.stringify(report)).not.toContain("approval");
  });

  it("fails doctor on unsafe ownership, modes, sudoers content, and visudo validation", async () => {
    const badHelper = await runPrivilegedHelperDoctor({
      config: doctorConfig(),
      fs: makeDoctorFs({
        stats: {
          [PRIVILEGED_HELPER_INSTALL_PATH]: fakeStat({ mode: 0o100775 }),
        },
      }),
    });
    expect(badHelper.checks.find((check) => check.name === "helper")).toMatchObject({
      status: "fail",
      message: "path must not be group/world writable",
    });

    const wrongOwner = await runPrivilegedHelperDoctor({
      config: doctorConfig(),
      fs: makeDoctorFs({
        stats: {
          [requestStateDir]: fakeStat({ directory: true, mode: 0o40750, uid: 501, gid: 20 }),
        },
      }),
    });
    expect(wrongOwner.checks.find((check) => check.name === "state")).toMatchObject({
      status: "fail",
      message: "owner 501:20 does not match expected 0:0",
    });

    const badSudoersContent = await runPrivilegedHelperDoctor({
      config: doctorConfig(),
      fs: makeDoctorFs({
        sudoersContent: "mike ALL = (root) NOPASSWD: ALL\n",
      }),
    });
    expect(badSudoersContent.checks.find((check) => check.name === "sudoers")).toMatchObject({
      status: "fail",
      message: "sudoers content does not match exact helper entry",
    });

    const badVisudo = await runPrivilegedHelperDoctor({
      config: doctorConfig(),
      fs: makeDoctorFs(),
      visudo: async (params): Promise<PrivilegedHelperDoctorCheck> => ({
        name: "sudoers",
        status: "fail",
        path: params.sudoersPath,
        message: "visudo -cf failed",
      }),
    });
    expect(badVisudo.checks.find((check) => check.name === "sudoers")).toMatchObject({
      status: "fail",
      message: "visudo -cf failed",
    });
  });
});
