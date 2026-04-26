import { describe, expect, it } from "vitest";
import {
  makeIsolatedAgentTurnJob,
  makeIsolatedAgentTurnParams,
  setupRunCronIsolatedAgentTurnSuite,
} from "./run.suite-helpers.js";
import {
  isCliProviderMock,
  loadRunCronIsolatedAgentTurn,
  runCliAgentMock,
  runWithModelFallbackMock,
} from "./run.test-harness.js";

const runCronIsolatedAgentTurn = await loadRunCronIsolatedAgentTurn();

describe("runCronIsolatedAgentTurn — CLI lightweight context", () => {
  setupRunCronIsolatedAgentTurnSuite();

  it("passes payload.lightContext through to CLI cron runs", async () => {
    isCliProviderMock.mockReturnValue(true);
    runWithModelFallbackMock.mockImplementation(async ({ provider, model, run }) => {
      const result = await run(provider, model);
      return { result, provider, model, attempts: [] };
    });
    runCliAgentMock.mockResolvedValue({
      payloads: [{ text: "done" }],
      meta: { agentMeta: { usage: { input: 10, output: 20 } } },
    });

    const result = await runCronIsolatedAgentTurn(
      makeIsolatedAgentTurnParams({
        job: makeIsolatedAgentTurnJob({
          sessionTarget: "isolated",
          payload: {
            kind: "agentTurn",
            message: "run the maintenance job",
            model: "openai-codex/gpt-5.5",
            lightContext: true,
          },
        }),
      }),
    );

    expect(result.status).toBe("ok");
    expect(runCliAgentMock).toHaveBeenCalledOnce();
    expect(runCliAgentMock.mock.calls[0][0]).toMatchObject({
      trigger: "cron",
      bootstrapContextMode: "lightweight",
      bootstrapContextRunKind: "cron",
    });
  });

  it("retries CLI cron runs with lightweight bootstrap after context overflow", async () => {
    isCliProviderMock.mockReturnValue(true);
    runWithModelFallbackMock.mockImplementation(async ({ provider, model, run }) => {
      const result = await run(provider, model);
      return { result, provider, model, attempts: [] };
    });
    runCliAgentMock
      .mockRejectedValueOnce(new Error("Context overflow: prompt too large for the model."))
      .mockResolvedValueOnce({
        payloads: [{ text: "done after retry" }],
        meta: { agentMeta: { usage: { input: 10, output: 20 } } },
      });

    const result = await runCronIsolatedAgentTurn(
      makeIsolatedAgentTurnParams({
        job: makeIsolatedAgentTurnJob({
          sessionTarget: "isolated",
          payload: {
            kind: "agentTurn",
            message: "run the maintenance job",
            model: "openai-codex/gpt-5.5",
          },
        }),
      }),
    );

    expect(result.status).toBe("ok");
    expect(runCliAgentMock).toHaveBeenCalledTimes(2);
    expect(runCliAgentMock.mock.calls[0][0].bootstrapContextMode).toBeUndefined();
    expect(runCliAgentMock.mock.calls[1][0]).toMatchObject({
      bootstrapContextMode: "lightweight",
      bootstrapContextRunKind: "cron",
    });
  });
});
