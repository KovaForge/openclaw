import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";

import {
  buildPrivilegedActionBinding,
  normalizePrivilegedActionBrewPath,
  type PrivilegedActionBinding,
  type PrivilegedActionBrewPath,
  type PrivilegedActionDecisionBinding,
  type PrivilegedActionRequest,
  verifyPrivilegedActionExecution,
} from "./privileged-actions.js";

export const PRIVILEGED_HELPER_SOURCE_LOCATION = "src/infra/privileged-action-helper.ts" as const;
export const PRIVILEGED_HELPER_CLI_SOURCE_LOCATION = "src/infra/privileged-action-helper-cli.ts" as const;
export const PRIVILEGED_HELPER_INSTALL_PATH = "/usr/local/libexec/openclaw-privileged-helper" as const;
export const PRIVILEGED_HELPER_DEFAULT_CONFIG_PATH = "/Library/Application Support/OpenClaw/privileged-actions.json" as const;
export const PRIVILEGED_HELPER_DEFAULT_STATE_DIR = "/var/run/openclaw/privileged" as const;
export const PRIVILEGED_HELPER_MAX_REQUEST_AGE_MS = 5 * 60 * 1000;
export const PRIVILEGED_HELPER_FUTURE_MTIME_SKEW_MS = 30 * 1000;

export type PrivilegedHelperCliCommand =
  | { kind: "request"; requestId: string }
  | { kind: "doctor"; json: true };

export type PrivilegedHelperConfig = {
  helperPath: string;
  helperVersion?: string | null;
  helperHash?: string | null;
  brewPath: PrivilegedActionBrewPath;
  requestStateDir: string;
  consumedStateDir?: string;
  authorizedApprovers: readonly string[];
  maxRequestAgeMs?: number;
  futureMtimeSkewMs?: number;
  configPath?: string;
  sudoersPath?: string;
  sudoersUser?: string;
  expectedOwnerUid?: number;
  expectedGroupGid?: number;
};

export type PrivilegedActionHelperRequestRecord = {
  request: PrivilegedActionRequest;
  binding: PrivilegedActionBinding;
  decision: PrivilegedActionDecisionBinding | null;
};

export type PrivilegedHelperExecutionPlan = {
  requestId: string;
  executable: PrivilegedActionBrewPath;
  argv: ["install", string];
  shell: false;
  env: Record<string, string>;
};

export type PrivilegedHelperSpawnResult = {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
};

export type PrivilegedHelperSpawn = (
  executable: PrivilegedActionBrewPath,
  argv: readonly string[],
  options: { shell: false; env: Record<string, string> },
) => Promise<PrivilegedHelperSpawnResult>;

export type PrivilegedHelperCliResult =
  | { ok: true; kind: "doctor"; report: PrivilegedHelperDoctorReport }
  | { ok: true; kind: "request"; plan: PrivilegedHelperExecutionPlan; result: PrivilegedHelperSpawnResult }
  | { ok: false; code: string; message: string };

export type PrivilegedHelperResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: string; message: string };

export type PrivilegedHelperDoctorCheck = {
  name: "helper" | "config" | "state" | "brew" | "sudoers";
  status: "pass" | "warn" | "fail";
  path: string;
  message: string;
};

export type PrivilegedHelperVisudoCheck = (params: {
  sudoersPath: string;
  expectedEntry: string;
}) => Promise<PrivilegedHelperDoctorCheck>;

export type PrivilegedHelperDoctorReport = {
  ok: boolean;
  helperSource: typeof PRIVILEGED_HELPER_SOURCE_LOCATION;
  installPath: string;
  checks: PrivilegedHelperDoctorCheck[];
};

type RequestFileMeta = {
  isSymbolicLink(): boolean;
  isFile(): boolean;
  isDirectory?(): boolean;
  mode: number;
  mtimeMs: number;
  uid?: number;
  gid?: number;
};

type HelperFs = {
  lstat(filePath: string): Promise<RequestFileMeta>;
  readFile(filePath: string, encoding: BufferEncoding): Promise<string>;
  rename(oldPath: string, newPath: string): Promise<void>;
  mkdir(dirPath: string, options: { recursive: true }): Promise<unknown>;
  access(filePath: string, mode?: number): Promise<void>;
};

type RawPrivilegedHelperConfig = Partial<{
  helperPath: unknown;
  helperVersion: unknown;
  helperHash: unknown;
  brewPath: unknown;
  requestStateDir: unknown;
  consumedStateDir: unknown;
  authorizedApprovers: unknown;
  maxRequestAgeMs: unknown;
  futureMtimeSkewMs: unknown;
  configPath: unknown;
  sudoersPath: unknown;
  sudoersUser: unknown;
  expectedOwnerUid: unknown;
  expectedGroupGid: unknown;
}>;

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

function isSafeRequestId(requestId: string): boolean {
  return REQUEST_ID_PATTERN.test(requestId) && requestId !== "." && requestId !== "..";
}

function err<T = never>(code: string, message: string): PrivilegedHelperResult<T> {
  return { ok: false, code, message };
}

function fsAdapter(): HelperFs {
  return {
    lstat: (filePath) => fs.lstat(filePath),
    readFile: (filePath, encoding) => fs.readFile(filePath, encoding),
    rename: (oldPath, newPath) => fs.rename(oldPath, newPath),
    mkdir: (dirPath, options) => fs.mkdir(dirPath, options),
    access: (filePath, mode) => fs.access(filePath, mode),
  };
}

function minimalHomebrewEnv(): Record<string, string> {
  return {
    HOME: "/var/empty",
    LOGNAME: "root",
    SHELL: "/bin/sh",
    USER: "root",
  };
}

function sanitizeProcessText(value: string): string {
  return value
    .replace(/Bearer\s+[-._~+/A-Za-z0-9]+=*/gu, "Bearer [REDACTED]")
    .replace(/([A-Za-z0-9_]*TOKEN[A-Za-z0-9_]*=)[^\s]+/giu, "$1[REDACTED]")
    .replace(/([A-Za-z0-9_]*PASSWORD[A-Za-z0-9_]*=)[^\s]+/giu, "$1[REDACTED]");
}

function parseOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function parseOptionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function expectedOwnerUid(config: PrivilegedHelperConfig): number {
  return config.expectedOwnerUid ?? 0;
}

function expectedGroupGid(config: PrivilegedHelperConfig): number {
  return config.expectedGroupGid ?? 0;
}

function modeBits(mode: number): number {
  return mode & 0o777;
}

function hasOwnerData(stat: RequestFileMeta): stat is RequestFileMeta & { uid: number; gid: number } {
  return typeof stat.uid === "number" && typeof stat.gid === "number";
}

function expectedSudoersEntry(config: PrivilegedHelperConfig): PrivilegedHelperResult<string> {
  if (!config.sudoersUser || !/^[A-Za-z0-9._-]+$/u.test(config.sudoersUser)) {
    return err("PRIVILEGED_HELPER_SUDOERS_USER_MISSING", "sudoers user is missing or unsafe");
  }
  return {
    ok: true,
    value: `${config.sudoersUser} ALL = (root) NOPASSWD: ${config.helperPath}`,
  };
}

function exactSudoersContentMatches(content: string, expectedEntry: string): boolean {
  const lines = content
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  return lines.length === 1 && lines[0] === expectedEntry;
}

export function parsePrivilegedHelperCliArgv(argv: readonly string[]): PrivilegedHelperResult<PrivilegedHelperCliCommand> {
  if (argv.length === 2 && argv[0] === "--request") {
    const requestId = argv[1];
    if (!requestId || !isSafeRequestId(requestId)) {
      return err("PRIVILEGED_HELPER_INVALID_REQUEST_ID", "request id is missing or unsafe");
    }
    return { ok: true, value: { kind: "request", requestId } };
  }

  if (argv.length === 2 && argv[0] === "doctor" && argv[1] === "--json") {
    return { ok: true, value: { kind: "doctor", json: true } };
  }

  return err(
    "PRIVILEGED_HELPER_INVALID_ARGV",
    "expected exactly --request <id> or doctor --json",
  );
}

export function requestPathForId(stateDir: string, requestId: string): PrivilegedHelperResult<string> {
  if (!isSafeRequestId(requestId)) {
    return err("PRIVILEGED_HELPER_INVALID_REQUEST_ID", "request id is missing or unsafe");
  }
  return { ok: true, value: path.join(stateDir, `${requestId}.json`) };
}

function consumedPathForId(config: PrivilegedHelperConfig, requestId: string): PrivilegedHelperResult<string> {
  const dir = config.consumedStateDir ?? path.join(config.requestStateDir, "consumed");
  const safe = requestPathForId(dir, requestId);
  return safe;
}

export function validatePrivilegedHelperConfig(config: PrivilegedHelperConfig): PrivilegedHelperResult<PrivilegedActionBrewPath> {
  const brewPath = normalizePrivilegedActionBrewPath(config.brewPath);
  if (!brewPath.ok) {
    return err(brewPath.code, brewPath.message);
  }
  if (!config.helperPath || config.helperPath !== PRIVILEGED_HELPER_INSTALL_PATH) {
    return err(
      "PRIVILEGED_HELPER_UNSUPPORTED_PATH",
      "helper path must be pinned to /usr/local/libexec/openclaw-privileged-helper",
    );
  }
  if (config.authorizedApprovers.length === 0) {
    return err("PRIVILEGED_HELPER_NO_AUTHORIZED_APPROVERS", "authorized approver set is empty");
  }
  return { ok: true, value: brewPath.value };
}

export function parsePrivilegedHelperConfig(
  raw: RawPrivilegedHelperConfig,
  configPath = PRIVILEGED_HELPER_DEFAULT_CONFIG_PATH,
): PrivilegedHelperResult<PrivilegedHelperConfig> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return err("PRIVILEGED_HELPER_CONFIG_MALFORMED", "helper config must be an object");
  }
  if (typeof raw.helperPath !== "string" || typeof raw.brewPath !== "string") {
    return err("PRIVILEGED_HELPER_CONFIG_MALFORMED", "helperPath and brewPath are required strings");
  }
  if (typeof raw.requestStateDir !== "string" || raw.requestStateDir.length === 0) {
    return err("PRIVILEGED_HELPER_CONFIG_MALFORMED", "requestStateDir is required");
  }
  if (
    !Array.isArray(raw.authorizedApprovers) ||
    !raw.authorizedApprovers.every((entry) => typeof entry === "string" && entry.length > 0)
  ) {
    return err("PRIVILEGED_HELPER_CONFIG_MALFORMED", "authorizedApprovers must be a non-empty string array");
  }

  const config: PrivilegedHelperConfig = {
    helperPath: raw.helperPath,
    helperVersion: parseOptionalString(raw.helperVersion),
    helperHash: parseOptionalString(raw.helperHash),
    brewPath: raw.brewPath as PrivilegedActionBrewPath,
    requestStateDir: raw.requestStateDir,
    consumedStateDir: parseOptionalString(raw.consumedStateDir),
    authorizedApprovers: raw.authorizedApprovers,
    maxRequestAgeMs: parseOptionalNumber(raw.maxRequestAgeMs),
    futureMtimeSkewMs: parseOptionalNumber(raw.futureMtimeSkewMs),
    configPath,
    sudoersPath: parseOptionalString(raw.sudoersPath),
    sudoersUser: parseOptionalString(raw.sudoersUser),
    expectedOwnerUid: parseOptionalNumber(raw.expectedOwnerUid),
    expectedGroupGid: parseOptionalNumber(raw.expectedGroupGid),
  };
  const check = validatePrivilegedHelperConfig(config);
  if (!check.ok) {
    return check;
  }
  return { ok: true, value: config };
}

export async function loadPrivilegedHelperConfigFile(params: {
  configPath?: string;
  fs?: HelperFs;
}): Promise<PrivilegedHelperResult<PrivilegedHelperConfig>> {
  const configPath = params.configPath ?? PRIVILEGED_HELPER_DEFAULT_CONFIG_PATH;
  const io = params.fs ?? fsAdapter();
  let raw: unknown;
  try {
    raw = JSON.parse(await io.readFile(configPath, "utf8"));
  } catch {
    return err("PRIVILEGED_HELPER_CONFIG_MALFORMED", "helper config is missing or invalid JSON");
  }
  return parsePrivilegedHelperConfig(raw as RawPrivilegedHelperConfig, configPath);
}

function parseRecord(raw: string): PrivilegedHelperResult<PrivilegedActionHelperRequestRecord> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return err("PRIVILEGED_HELPER_MALFORMED_JSON", "request record is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return err("PRIVILEGED_HELPER_MALFORMED_JSON", "request record must be an object");
  }
  const record = parsed as Partial<PrivilegedActionHelperRequestRecord>;
  if (!record.request || !record.binding || !("decision" in record)) {
    return err("PRIVILEGED_HELPER_MALFORMED_JSON", "request record is missing request, binding, or decision");
  }
  return { ok: true, value: record as PrivilegedActionHelperRequestRecord };
}

function validateRecordMtime(params: {
  nowMs: number;
  mtimeMs: number;
  request: PrivilegedActionRequest;
  maxAgeMs: number;
  futureSkewMs: number;
}): PrivilegedHelperResult<void> {
  if (params.mtimeMs > params.nowMs + params.futureSkewMs) {
    return err("PRIVILEGED_HELPER_FUTURE_MTIME", "request file mtime is unexpectedly in the future");
  }
  if (params.nowMs - params.mtimeMs > params.maxAgeMs) {
    return err("PRIVILEGED_HELPER_STALE_MTIME", "request file mtime is older than the helper freshness bound");
  }
  if (params.mtimeMs + params.futureSkewMs < params.request.createdAtMs) {
    return err("PRIVILEGED_HELPER_STALE_MTIME", "request file mtime predates the approval window");
  }
  if (params.mtimeMs > params.request.expiresAtMs + params.futureSkewMs) {
    return err("PRIVILEGED_HELPER_STALE_MTIME", "request file mtime is outside the approval window");
  }
  return { ok: true, value: undefined };
}

export function validatePrivilegedHelperRequestRecord(params: {
  config: PrivilegedHelperConfig;
  record: PrivilegedActionHelperRequestRecord;
  nowMs: number;
  mtimeMs: number;
  consumedRequestIds?: ReadonlySet<string>;
}): PrivilegedHelperResult<PrivilegedHelperExecutionPlan> {
  const configCheck = validatePrivilegedHelperConfig(params.config);
  if (!configCheck.ok) {
    return configCheck;
  }

  const { request, binding, decision } = params.record;
  if (!request || request.id !== binding.requestId) {
    return err("PRIVILEGED_HELPER_BINDING_MISMATCH", "request id does not match binding");
  }
  if (request.helper.path !== params.config.helperPath) {
    return err("PRIVILEGED_HELPER_BINDING_MISMATCH", "request helper path does not match config");
  }
  if ((request.helper.brewPath ?? params.config.brewPath) !== params.config.brewPath) {
    return err("PRIVILEGED_HELPER_BREW_PATH_MISMATCH", "request brew path does not match config");
  }
  if (params.config.helperVersion && request.helper.version !== params.config.helperVersion) {
    return err("PRIVILEGED_HELPER_BINDING_MISMATCH", "request helper version does not match config");
  }
  if (params.config.helperHash && request.helper.hash !== params.config.helperHash) {
    return err("PRIVILEGED_HELPER_BINDING_MISMATCH", "request helper hash does not match config");
  }

  const mtimeCheck = validateRecordMtime({
    nowMs: params.nowMs,
    mtimeMs: params.mtimeMs,
    request,
    maxAgeMs: params.config.maxRequestAgeMs ?? PRIVILEGED_HELPER_MAX_REQUEST_AGE_MS,
    futureSkewMs: params.config.futureMtimeSkewMs ?? PRIVILEGED_HELPER_FUTURE_MTIME_SKEW_MS,
  });
  if (!mtimeCheck.ok) {
    return mtimeCheck;
  }

  const reconstructed = buildPrivilegedActionBinding(request);
  const executionCheck = verifyPrivilegedActionExecution({
    expected: reconstructed,
    actual: binding,
    decision,
    nowMs: params.nowMs,
    authorizedApprovers: new Set(params.config.authorizedApprovers),
    consumedRequestIds: params.consumedRequestIds,
  });
  if (!executionCheck.ok) {
    return err(executionCheck.code, executionCheck.message);
  }

  if (request.action.verb !== "homebrew.install") {
    return err("PRIVILEGED_HELPER_UNSUPPORTED_VERB", "only homebrew.install is supported");
  }

  return {
    ok: true,
    value: {
      requestId: request.id,
      executable: configCheck.value,
      argv: ["install", request.action.args.formula],
      shell: false,
      env: minimalHomebrewEnv(),
    },
  };
}

export async function consumePrivilegedActionRequestFile(params: {
  config: PrivilegedHelperConfig;
  requestId: string;
  nowMs: number;
  fs?: HelperFs;
}): Promise<PrivilegedHelperResult<PrivilegedHelperExecutionPlan>> {
  const command = parsePrivilegedHelperCliArgv(["--request", params.requestId]);
  if (!command.ok) {
    return command;
  }
  const requestPath = requestPathForId(params.config.requestStateDir, params.requestId);
  if (!requestPath.ok) {
    return requestPath;
  }
  const consumedPath = consumedPathForId(params.config, params.requestId);
  if (!consumedPath.ok) {
    return consumedPath;
  }

  const io = params.fs ?? fsAdapter();
  let stat: RequestFileMeta;
  try {
    stat = await io.lstat(requestPath.value);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      try {
        await io.lstat(consumedPath.value);
        return err("PRIVILEGED_ACTION_REPLAY", "privileged action already consumed");
      } catch {
        return err("PRIVILEGED_HELPER_REQUEST_MISSING", "request file does not exist");
      }
    }
    throw e;
  }

  if (stat.isSymbolicLink()) {
    return err("PRIVILEGED_HELPER_REQUEST_SYMLINK", "request file must not be a symlink");
  }
  if (!stat.isFile()) {
    return err("PRIVILEGED_HELPER_REQUEST_NOT_FILE", "request path must be a regular file");
  }
  if ((stat.mode & 0o022) !== 0) {
    return err("PRIVILEGED_HELPER_REQUEST_WRITABLE", "request file must not be group/world writable");
  }
  if (
    hasOwnerData(stat) &&
    params.config.expectedOwnerUid !== undefined &&
    params.config.expectedGroupGid !== undefined &&
    (stat.uid !== params.config.expectedOwnerUid || stat.gid !== params.config.expectedGroupGid)
  ) {
    return err("PRIVILEGED_HELPER_REQUEST_OWNER", "request file owner/group does not match trusted config");
  }

  const parsed = parseRecord(await io.readFile(requestPath.value, "utf8"));
  if (!parsed.ok) {
    return parsed;
  }
  const plan = validatePrivilegedHelperRequestRecord({
    config: params.config,
    record: parsed.value,
    nowMs: params.nowMs,
    mtimeMs: stat.mtimeMs,
  });
  if (!plan.ok) {
    return plan;
  }

  await io.mkdir(path.dirname(consumedPath.value), { recursive: true });
  await io.rename(requestPath.value, consumedPath.value);
  return plan;
}

async function checkPath(params: {
  name: PrivilegedHelperDoctorCheck["name"];
  path: string;
  fs: HelperFs;
  executable?: boolean;
}): Promise<PrivilegedHelperDoctorCheck> {
  try {
    await params.fs.access(params.path, params.executable ? 0o111 : undefined);
    return { name: params.name, status: "pass", path: params.path, message: "present" };
  } catch {
    return { name: params.name, status: "fail", path: params.path, message: "missing or inaccessible" };
  }
}

async function checkOwnedPath(params: {
  name: PrivilegedHelperDoctorCheck["name"];
  path: string;
  fs: HelperFs;
  config: PrivilegedHelperConfig;
  executable?: boolean;
  directory?: boolean;
  maxMode?: number;
}): Promise<PrivilegedHelperDoctorCheck> {
  try {
    const stat = await params.fs.lstat(params.path);
    if (stat.isSymbolicLink()) {
      return { name: params.name, status: "fail", path: params.path, message: "path must not be a symlink" };
    }
    if (params.directory) {
      if (!stat.isDirectory?.()) {
        return { name: params.name, status: "fail", path: params.path, message: "path must be a directory" };
      }
    } else if (!stat.isFile()) {
      return { name: params.name, status: "fail", path: params.path, message: "path must be a regular file" };
    }
    if ((stat.mode & 0o022) !== 0) {
      return { name: params.name, status: "fail", path: params.path, message: "path must not be group/world writable" };
    }
    if (params.executable && (stat.mode & 0o111) === 0) {
      return { name: params.name, status: "fail", path: params.path, message: "path must be executable" };
    }
    if (params.maxMode !== undefined && (modeBits(stat.mode) | params.maxMode) !== params.maxMode) {
      return {
        name: params.name,
        status: "fail",
        path: params.path,
        message: `mode ${modeBits(stat.mode).toString(8)} is broader than ${params.maxMode.toString(8)}`,
      };
    }
    if (hasOwnerData(stat)) {
      const expectedUid = expectedOwnerUid(params.config);
      const expectedGid = expectedGroupGid(params.config);
      if (stat.uid !== expectedUid || stat.gid !== expectedGid) {
        return {
          name: params.name,
          status: "fail",
          path: params.path,
          message: `owner ${stat.uid}:${stat.gid} does not match expected ${expectedUid}:${expectedGid}`,
        };
      }
    }
    return { name: params.name, status: "pass", path: params.path, message: "ownership and mode ok" };
  } catch {
    return { name: params.name, status: "fail", path: params.path, message: "missing or inaccessible" };
  }
}

async function checkSudoers(params: {
  config: PrivilegedHelperConfig;
  fs: HelperFs;
  visudo?: PrivilegedHelperVisudoCheck;
}): Promise<PrivilegedHelperDoctorCheck> {
  const sudoersPath = params.config.sudoersPath ?? "/etc/sudoers.d/openclaw-privileged-helper";
  const expected = expectedSudoersEntry(params.config);
  if (!expected.ok) {
    return { name: "sudoers", status: "fail", path: sudoersPath, message: expected.message };
  }
  const pathCheck = await checkOwnedPath({
    name: "sudoers",
    path: sudoersPath,
    fs: params.fs,
    config: params.config,
    maxMode: 0o440,
  });
  if (pathCheck.status !== "pass") {
    return pathCheck;
  }
  let content: string;
  try {
    content = await params.fs.readFile(sudoersPath, "utf8");
  } catch {
    return { name: "sudoers", status: "fail", path: sudoersPath, message: "sudoers entry is unreadable" };
  }
  if (!exactSudoersContentMatches(content, expected.value)) {
    return { name: "sudoers", status: "fail", path: sudoersPath, message: "sudoers content does not match exact helper entry" };
  }
  if (params.visudo) {
    const visudo = await params.visudo({ sudoersPath, expectedEntry: expected.value });
    if (visudo.status !== "pass") {
      return visudo;
    }
  }
  return { name: "sudoers", status: "pass", path: sudoersPath, message: "exact entry and validation ok" };
}

export function executePrivilegedHelperPlan(params: {
  plan: PrivilegedHelperExecutionPlan;
  spawn?: PrivilegedHelperSpawn;
}): Promise<PrivilegedHelperSpawnResult> {
  const spawnImpl = params.spawn ?? spawnPrivilegedHelperProcess;
  return spawnImpl(params.plan.executable, params.plan.argv, {
    shell: false,
    env: params.plan.env,
  });
}

function spawnPrivilegedHelperProcess(
  executable: PrivilegedActionBrewPath,
  argv: readonly string[],
  options: { shell: false; env: Record<string, string> },
): Promise<PrivilegedHelperSpawnResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [...argv], {
      env: options.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr?.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      resolve({
        code,
        signal,
        stdout: sanitizeProcessText(stdout),
        stderr: sanitizeProcessText(stderr),
      });
    });
  });
}

export async function runPrivilegedHelperCliCommand(params: {
  argv: readonly string[];
  config: PrivilegedHelperConfig;
  nowMs?: number;
  fs?: HelperFs;
  spawn?: PrivilegedHelperSpawn;
}): Promise<PrivilegedHelperCliResult> {
  const command = parsePrivilegedHelperCliArgv(params.argv);
  if (!command.ok) {
    return command;
  }
  if (command.value.kind === "doctor") {
    return {
      ok: true,
      kind: "doctor",
      report: await runPrivilegedHelperDoctor({ config: params.config, fs: params.fs }),
    };
  }

  const plan = await consumePrivilegedActionRequestFile({
    config: params.config,
    requestId: command.value.requestId,
    nowMs: params.nowMs ?? Date.now(),
    fs: params.fs,
  });
  if (!plan.ok) {
    return plan;
  }
  const result = await executePrivilegedHelperPlan({ plan: plan.value, spawn: params.spawn });
  if (result.code !== 0) {
    return {
      ok: false,
      code: "PRIVILEGED_HELPER_BREW_FAILED",
      message: `brew exited with code ${String(result.code)}`,
    };
  }
  return { ok: true, kind: "request", plan: plan.value, result };
}

export async function runPrivilegedHelperDoctor(params: {
  config: PrivilegedHelperConfig;
  fs?: HelperFs;
  visudo?: PrivilegedHelperVisudoCheck;
}): Promise<PrivilegedHelperDoctorReport> {
  const io = params.fs ?? fsAdapter();
  const checks: PrivilegedHelperDoctorCheck[] = [];

  checks.push(
    await checkOwnedPath({
      name: "helper",
      path: params.config.helperPath,
      fs: io,
      config: params.config,
      executable: true,
    }),
  );
  if (params.config.configPath) {
    checks.push(
      await checkOwnedPath({
        name: "config",
        path: params.config.configPath,
        fs: io,
        config: params.config,
      }),
    );
  } else {
    checks.push({ name: "config", status: "warn", path: "", message: "config path is not set" });
  }
  checks.push(
    await checkOwnedPath({
      name: "state",
      path: params.config.requestStateDir,
      fs: io,
      config: params.config,
      directory: true,
      maxMode: 0o750,
    }),
  );
  checks.push(await checkPath({ name: "brew", path: params.config.brewPath, fs: io, executable: true }));
  checks.push(await checkSudoers({ config: params.config, fs: io, visudo: params.visudo }));

  return {
    ok: checks.every((check) => check.status !== "fail"),
    helperSource: PRIVILEGED_HELPER_SOURCE_LOCATION,
    installPath: params.config.helperPath,
    checks,
  };
}
