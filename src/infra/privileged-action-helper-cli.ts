#!/usr/bin/env node

import {
  loadPrivilegedHelperConfigFile,
  PRIVILEGED_HELPER_DEFAULT_CONFIG_PATH,
  runPrivilegedHelperCliCommand,
} from "./privileged-action-helper.js";

async function main() {
  const configPath = process.env.OPENCLAW_PRIVILEGED_CONFIG_PATH ?? PRIVILEGED_HELPER_DEFAULT_CONFIG_PATH;
  const config = await loadPrivilegedHelperConfigFile({ configPath });
  if (!config.ok) {
    console.error(JSON.stringify(config));
    process.exitCode = 1;
    return;
  }

  const result = await runPrivilegedHelperCliCommand({
    argv: process.argv.slice(2),
    config: config.value,
  });
  console.log(JSON.stringify(result));
  process.exitCode = result.ok ? 0 : 1;
}

main().catch((error: unknown) => {
  console.error(
    JSON.stringify({
      ok: false,
      code: "PRIVILEGED_HELPER_FATAL",
      message: error instanceof Error ? error.message : String(error),
    }),
  );
  process.exitCode = 1;
});
