export type PrivilegedActionApprovalTarget = "dm";
export type PrivilegedActionBrewPath = "/usr/local/bin/brew" | "/opt/homebrew/bin/brew";

export type PrivilegedActionApprovalConfig = {
  /** MVP is DM-only to avoid leaking privileged action metadata in guild channels. */
  target?: PrivilegedActionApprovalTarget;
  /** Discord user IDs allowed to approve privileged actions. */
  approvers?: string[];
  /** Optional agent IDs allowed to request privileged actions. */
  agentFilter?: string[];
  /** Optional session key filters for privileged action requests. */
  sessionFilter?: string[];
};

export type PrivilegedActionsConfig = {
  enabled?: boolean;
  /**
   * Gatekeeper invariant: privileged actions never collect, store, or relay sudo
   * passwords through chat approval surfaces.
   */
  passwordPrompt?: false;
  approval?: PrivilegedActionApprovalConfig;
  helper?: {
    mode?: "sudoers";
    path?: string;
    /** Pinned Homebrew executable path. PATH lookup is not allowed. */
    brewPath?: PrivilegedActionBrewPath;
    configPath?: string;
    version?: string;
    hash?: string;
  };
  verbs?: {
    homebrew?: {
      install?: {
        enabled?: boolean;
        formulaAllowlist?: string[];
      };
    };
  };
};
