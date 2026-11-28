import { afterEach } from "vitest";
import { resetRateLimitCooldowns } from "./src/runtime/llm-api/retry.js";

// The provider cooldown after a 429 is process-wide on purpose. A test that provokes one must not hold back the next test.
afterEach(() => resetRateLimitCooldowns());
