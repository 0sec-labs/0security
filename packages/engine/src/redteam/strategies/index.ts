export type { Placement, Strategy, StrategyFamily, StrategyInput, StrategyVariant } from "./types.js";
export { applyChecked, BASELINE_ID, listStrategies, MAX_VARIANT_COUNT, strategiesByFamily, strategyById, type CheckedVariants } from "./registry.js";
export { isReservedHost, lintPayload, safetyProblems, MAX_PAYLOAD_LENGTH, type LintOptions, type LintResult, type SafetyOptions } from "./lint.js";
export { liftOverBaseline, type LiftRow, type StrategyOutcome } from "./lift.js";
export { foldHomoglyphs, fromBase64, fromHex, reverseText, rot13, stripZeroWidth, toBase64, toHex } from "./transforms.js";
export { makeRng, type Rng } from "./rng.js";
