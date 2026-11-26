// Side-effect module: imported right after apply-env-aliases so the handlers
// exist before the engine and command modules evaluate (a crash while loading
// them is captured too). `0` and no-argument launches are the web surface.
import { crashCommandFromArgv, installCrashCapture } from "./crash-capture.js";
import { surfaceFromArgv } from "./surface.js";

installCrashCapture({
  surface: surfaceFromArgv(process.argv),
  // The anonymous usage pipeline records only a finite `crash` category (no message, no stack).
  // It is a no-op below the usage tier or without a PostHog destination.
  onCrash: async () => {
    const { analyticsPipeline } = await import("@0/engine");
    analyticsPipeline.recordLifecycle({ event: "error_exit", category: "crash", command: crashCommandFromArgv(process.argv) });
    await analyticsPipeline.flushNow();
  },
});
