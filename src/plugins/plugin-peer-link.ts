import fs from "node:fs/promises";
import path from "node:path";
import { resolveOpenClawPackageRootSync } from "../infra/openclaw-root.js";

type PluginPeerLinkLogger = {
  info?: (message: string) => void;
  warn?: (message: string) => void;
};

type RelinkManagedNpmRootResult = {
  checked: number;
  attempted: number;
};

export type OpenClawPeerDependencyLinkIssueReason =
  | "host-root-unresolved"
  | "missing"
  | "unreadable"
  | "wrong-target";

export type OpenClawPeerDependencyLinkIssue = {
  packageDir: string;
  packageName: string;
  peerName: "openclaw";
  linkPath: string;
  reason: OpenClawPeerDependencyLinkIssueReason;
  expectedTarget?: string;
  actualTarget?: string;
  error?: string;
};

export type OpenClawPeerDependencyLinkAudit = {
  checked: number;
  issues: OpenClawPeerDependencyLinkIssue[];
};

export type RepairOpenClawPeerDependencyLinksResult = {
  checked: number;
  attempted: number;
  issuesBefore: OpenClawPeerDependencyLinkIssue[];
  issuesAfter: OpenClawPeerDependencyLinkIssue[];
};

function readStringRecord(value: unknown): Record<string, string> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return {};
  }
  const record: Record<string, string> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw === "string") {
      record[key] = raw;
    }
  }
  return record;
}

async function readPackagePeerDependencies(packageDir: string): Promise<Record<string, string>> {
  try {
    const raw = await fs.readFile(path.join(packageDir, "package.json"), "utf8");
    const parsed = JSON.parse(raw) as { peerDependencies?: unknown };
    return readStringRecord(parsed.peerDependencies);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return {};
    }
    throw error;
  }
}

async function listManagedNpmRootPackageDirs(npmRoot: string): Promise<string[]> {
  const nodeModulesDir = path.join(npmRoot, "node_modules");
  let entries: import("node:fs").Dirent[];
  try {
    entries = await fs.readdir(nodeModulesDir, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }
    throw error;
  }

  const packageDirs: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name === ".bin") {
      continue;
    }
    const entryPath = path.join(nodeModulesDir, entry.name);
    if (entry.name.startsWith("@")) {
      const scopedEntries = await fs.readdir(entryPath, { withFileTypes: true }).catch((error) => {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") {
          return [];
        }
        throw error;
      });
      for (const scopedEntry of scopedEntries) {
        if (scopedEntry.isDirectory()) {
          packageDirs.push(path.join(entryPath, scopedEntry.name));
        }
      }
      continue;
    }
    if (!entry.name.startsWith(".")) {
      packageDirs.push(entryPath);
    }
  }
  return packageDirs.toSorted((a, b) => a.localeCompare(b));
}

function packageNameFromDir(packageDir: string): string {
  const name = path.basename(packageDir);
  const scope = path.basename(path.dirname(packageDir));
  return scope.startsWith("@") ? `${scope}/${name}` : name;
}

function resolveHostRoot(): string | null {
  return resolveOpenClawPackageRootSync({
    argv1: process.argv[1],
    moduleUrl: import.meta.url,
    cwd: process.cwd(),
  });
}

async function realpathOrIssue(params: {
  packageDir: string;
  linkPath: string;
  hostRoot: string;
}): Promise<OpenClawPeerDependencyLinkIssue | null> {
  let expectedTarget: string;
  try {
    expectedTarget = await fs.realpath(params.hostRoot);
  } catch (err) {
    return {
      packageDir: params.packageDir,
      packageName: packageNameFromDir(params.packageDir),
      peerName: "openclaw",
      linkPath: params.linkPath,
      reason: "host-root-unresolved",
      expectedTarget: params.hostRoot,
      error: String(err),
    };
  }

  let actualTarget: string;
  try {
    actualTarget = await fs.realpath(params.linkPath);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    return {
      packageDir: params.packageDir,
      packageName: packageNameFromDir(params.packageDir),
      peerName: "openclaw",
      linkPath: params.linkPath,
      reason: code === "ENOENT" || code === "ENOTDIR" ? "missing" : "unreadable",
      expectedTarget,
      error: String(err),
    };
  }

  if (actualTarget !== expectedTarget) {
    return {
      packageDir: params.packageDir,
      packageName: packageNameFromDir(params.packageDir),
      peerName: "openclaw",
      linkPath: params.linkPath,
      reason: "wrong-target",
      expectedTarget,
      actualTarget,
    };
  }

  return null;
}

/**
 * Symlink the host openclaw package for plugins that declare it as a peer.
 * Plugin package managers still own third-party dependencies; this only wires
 * the host SDK package into the plugin-local Node graph.
 */
export async function linkOpenClawPeerDependencies(params: {
  installedDir: string;
  peerDependencies: Record<string, string>;
  logger: PluginPeerLinkLogger;
}): Promise<void> {
  const peers = Object.keys(params.peerDependencies).filter((name) => name === "openclaw");
  if (peers.length === 0) {
    return;
  }

  const hostRoot = resolveHostRoot();
  if (!hostRoot) {
    params.logger.warn?.(
      "Could not locate openclaw package root to symlink peerDependencies; plugin may fail to resolve openclaw at runtime.",
    );
    return;
  }

  const nodeModulesDir = path.join(params.installedDir, "node_modules");
  await fs.mkdir(nodeModulesDir, { recursive: true });

  for (const peerName of peers) {
    const linkPath = path.join(nodeModulesDir, peerName);

    try {
      await fs.rm(linkPath, { recursive: true, force: true });
      await fs.symlink(hostRoot, linkPath, "junction");
      params.logger.info?.(`Linked peerDependency "${peerName}" -> ${hostRoot}`);
    } catch (err) {
      params.logger.warn?.(`Failed to symlink peerDependency "${peerName}": ${String(err)}`);
    }
  }
}

export async function relinkOpenClawPeerDependenciesInManagedNpmRoot(params: {
  npmRoot: string;
  logger: PluginPeerLinkLogger;
}): Promise<RelinkManagedNpmRootResult> {
  let checked = 0;
  let attempted = 0;
  for (const packageDir of await listManagedNpmRootPackageDirs(params.npmRoot)) {
    const peerDependencies = await readPackagePeerDependencies(packageDir);
    if (!Object.hasOwn(peerDependencies, "openclaw")) {
      continue;
    }
    checked += 1;
    await linkOpenClawPeerDependencies({
      installedDir: packageDir,
      peerDependencies,
      logger: params.logger,
    });
    attempted += 1;
  }
  return { checked, attempted };
}

export async function auditOpenClawPeerDependenciesInManagedNpmRoot(params: {
  npmRoot: string;
}): Promise<OpenClawPeerDependencyLinkAudit> {
  let checked = 0;
  const issues: OpenClawPeerDependencyLinkIssue[] = [];
  const hostRoot = resolveHostRoot();

  for (const packageDir of await listManagedNpmRootPackageDirs(params.npmRoot)) {
    const peerDependencies = await readPackagePeerDependencies(packageDir);
    if (!Object.hasOwn(peerDependencies, "openclaw")) {
      continue;
    }
    checked += 1;
    const linkPath = path.join(packageDir, "node_modules", "openclaw");
    if (!hostRoot) {
      issues.push({
        packageDir,
        packageName: packageNameFromDir(packageDir),
        peerName: "openclaw",
        linkPath,
        reason: "host-root-unresolved",
      });
      continue;
    }
    const issue = await realpathOrIssue({ packageDir, linkPath, hostRoot });
    if (issue) {
      issues.push(issue);
    }
  }

  return { checked, issues };
}

export async function repairOpenClawPeerDependencyLinkIssuesInManagedNpmRoot(params: {
  npmRoot: string;
  logger: PluginPeerLinkLogger;
}): Promise<RepairOpenClawPeerDependencyLinksResult> {
  const before = await auditOpenClawPeerDependenciesInManagedNpmRoot({
    npmRoot: params.npmRoot,
  });
  let attempted = 0;
  const packageDirs = new Set(before.issues.map((issue) => issue.packageDir));

  for (const packageDir of packageDirs) {
    const peerDependencies = await readPackagePeerDependencies(packageDir);
    if (!Object.hasOwn(peerDependencies, "openclaw")) {
      continue;
    }
    await linkOpenClawPeerDependencies({
      installedDir: packageDir,
      peerDependencies,
      logger: params.logger,
    });
    attempted += 1;
  }

  const after = await auditOpenClawPeerDependenciesInManagedNpmRoot({
    npmRoot: params.npmRoot,
  });
  return {
    checked: after.checked,
    attempted,
    issuesBefore: before.issues,
    issuesAfter: after.issues,
  };
}
