import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  auditOpenClawPeerDependenciesInManagedNpmRoot,
  repairOpenClawPeerDependencyLinkIssuesInManagedNpmRoot,
} from "./plugin-peer-link.js";

let tempRoot: string;

async function writePackage(npmRoot: string, packageName: string): Promise<string> {
  const packageDir = path.join(npmRoot, "node_modules", ...packageName.split("/"));
  await fs.mkdir(packageDir, { recursive: true });
  await fs.writeFile(
    path.join(packageDir, "package.json"),
    JSON.stringify(
      {
        name: packageName,
        version: "1.0.0",
        peerDependencies: {
          openclaw: "^2026.5.0",
        },
      },
      null,
      2,
    ),
  );
  return packageDir;
}

describe("OpenClaw plugin peer links", () => {
  beforeEach(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-peer-link-"));
  });

  afterEach(async () => {
    await fs.rm(tempRoot, { recursive: true, force: true });
  });

  it("audits and repairs missing openclaw peer links in managed npm plugins", async () => {
    const packageDir = await writePackage(tempRoot, "@openclaw/discord");

    const before = await auditOpenClawPeerDependenciesInManagedNpmRoot({ npmRoot: tempRoot });

    expect(before.checked).toBe(1);
    expect(before.issues).toMatchObject([
      {
        packageDir,
        packageName: "@openclaw/discord",
        peerName: "openclaw",
        reason: "missing",
      },
    ]);

    const info: string[] = [];
    const result = await repairOpenClawPeerDependencyLinkIssuesInManagedNpmRoot({
      npmRoot: tempRoot,
      logger: {
        info: (message) => info.push(message),
      },
    });

    expect(result.attempted).toBe(1);
    expect(result.issuesBefore).toHaveLength(1);
    expect(result.issuesAfter).toHaveLength(0);
    expect(info.join("\n")).toContain('Linked peerDependency "openclaw"');

    const after = await auditOpenClawPeerDependenciesInManagedNpmRoot({ npmRoot: tempRoot });
    expect(after).toEqual({ checked: 1, issues: [] });
  });

  it("detects and repairs openclaw peer links that point at the wrong package root", async () => {
    const packageDir = await writePackage(tempRoot, "@openclaw/codex");
    const wrongTarget = path.join(tempRoot, "wrong-openclaw");
    const linkPath = path.join(packageDir, "node_modules", "openclaw");
    await fs.mkdir(path.dirname(linkPath), { recursive: true });
    await fs.mkdir(wrongTarget, { recursive: true });
    await fs.symlink(wrongTarget, linkPath, "junction");

    const before = await auditOpenClawPeerDependenciesInManagedNpmRoot({ npmRoot: tempRoot });

    expect(before.checked).toBe(1);
    expect(before.issues).toMatchObject([
      {
        packageDir,
        packageName: "@openclaw/codex",
        peerName: "openclaw",
        reason: "wrong-target",
      },
    ]);

    const result = await repairOpenClawPeerDependencyLinkIssuesInManagedNpmRoot({
      npmRoot: tempRoot,
      logger: {},
    });

    expect(result.attempted).toBe(1);
    expect(result.issuesAfter).toHaveLength(0);
  });
});
