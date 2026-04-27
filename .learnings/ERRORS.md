# Errors

Command failures.

---

## [ERR-20260426-001] git_commit_index_lock

**Logged**: 2026-04-26T12:33:00+08:00
**Priority**: high
**Status**: pending

### Summary

Git commit failed because a stale `.git/index.lock` existed in the OpenClaw repo.

### Error

```text
fatal: Unable to create '/Users/mike/.openclaw/workspace/projects/openclaw/.git/index.lock': File exists.
```

### Context

Attempted to stage, commit, and push the CLI cron lightweight-context fix. Checked for active git/editor processes before removing the stale lock.

---
