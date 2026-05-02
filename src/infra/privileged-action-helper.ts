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
export const PRIVILEGED_HELPER_INSTALL_PATH = "/usr/local/libexec/openclaw-privileged-helper" as const;
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
};

export type PrivilegedHelperResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: string; message: string };

export type PrivilegedHelperDoctorCheck = {
  name: "helper" | "config" | "state" | "brew" | "sudoers";
  status: "pass" | "warn" | "fail";
  path: string;
  message: string;
};

export type PrivilegedHelperDoctorReport = {
  ok: boolean;
  helperSource: typeof PRIVILEGED_HELPER_SOURCE_LOCATION;
  installPath: string;
  checks: PrivilegedHelperDoctorCheck[];
};

type RequestFileMeta = {
  isSymbolicLink(): boolean;
  isFile(): boolean;
  mode: number;
  mtimeMs: number;
};

type HelperFs = {
  lstat(filePath: string): Promise<RequestFileMeta>;
  readFile(filePath: string, encoding: BufferEncoding): Promise<string>;
  rename(oldPath: string, newPath: string): Promise<void>;
  mkdir(dirPath: string, options: { recursive: true }): Promise<unknown>;
  access(filePath: string, mode?: number): Promise<void>;
};

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

export async function runPrivilegedHelperDoctor(params: {
  config: PrivilegedHelperConfig;
  fs?: HelperFs;
}): Promise<PrivilegedHelperDoctorReport> {
  const io = params.fs ?? fsAdapter();
  const checks: PrivilegedHelperDoctorCheck[] = [];

  checks.push(await checkPath({ name: "helper", path: params.config.helperPath, fs: io, executable: true }));
  if (params.config.configPath) {
    checks.push(await checkPath({ name: "config", path: params.config.configPath, fs: io }));
  } else {
    checks.push({ name: "config", status: "warn", path: "", message: "config path is not set" });
  }
  checks.push(await checkPath({ name: "state", path: params.config.requestStateDir, fs: io }));
  checks.push(await checkPath({ name: "brew", path: params.config.brewPath, fs: io, executable: true }));
  checks.push(
    await checkPath({
      name: "sudoers",
      path: params.config.sudoersPath ?? "/etc/sudoers.d/openclaw-privileged-helper",
      fs: io,
    }),
  );

  return {
    ok: checks.every((check) => check.status !== "fail"),
    helperSource: PRIVILEGED_HELPER_SOURCE_LOCATION,
    installPath: params.config.helperPath,
    checks,
  };
}
