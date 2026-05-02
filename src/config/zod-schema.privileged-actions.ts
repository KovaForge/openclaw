import { z } from "zod";

const PrivilegedActionApprovalSchema = z
  .object({
    // Gatekeeper MVP is DM-only; channel delivery leaks privileged host metadata.
    target: z.literal("dm").default("dm"),
    approvers: z.array(z.string()).optional(),
    agentFilter: z.array(z.string()).optional(),
    sessionFilter: z.array(z.string()).optional(),
  })
  .strict()
  .optional();

const PrivilegedActionHelperSchema = z
  .object({
    mode: z.literal("sudoers").optional(),
    path: z.string().min(1).optional(),
    // Helper MVP must use a pinned Homebrew path. PATH lookup and arbitrary paths are out.
    brewPath: z
      .union([z.literal("/usr/local/bin/brew"), z.literal("/opt/homebrew/bin/brew")])
      .optional(),
    configPath: z.string().min(1).optional(),
    version: z.string().min(1).optional(),
    hash: z.string().min(1).optional(),
  })
  .strict()
  .optional();

const PrivilegedActionHomebrewInstallSchema = z
  .object({
    enabled: z.boolean().optional(),
    formulaAllowlist: z.array(z.string()).optional(),
  })
  .strict()
  .optional();

export const PrivilegedActionsSchema = z
  .object({
    enabled: z.boolean().optional(),
    // Gatekeeper invariant: no sudo/password prompt may be enabled through Discord.
    passwordPrompt: z.literal(false).default(false),
    approval: PrivilegedActionApprovalSchema,
    helper: PrivilegedActionHelperSchema,
    verbs: z
      .object({
        homebrew: z
          .object({
            install: PrivilegedActionHomebrewInstallSchema,
          })
          .strict()
          .optional(),
      })
      .strict()
      .optional(),
  })
  .strict()
  .optional();
