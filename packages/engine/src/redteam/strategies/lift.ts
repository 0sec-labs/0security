/** Reports each strategy's hit rate as lift over the plain baseline S00, so no strategy is quoted without its control. */
import { BASELINE_ID } from "./registry.js";

export interface StrategyOutcome { strategyId: string; episodes: number; hits: number }
export interface LiftRow {
  strategyId: string;
  episodes: number;
  hits: number;
  hitRate: number;
  /** hitRate minus the baseline rate, in absolute points (0.25 means 25 points). */
  lift: number;
  /** hitRate divided by the baseline rate; null when the baseline rate is zero. */
  ratio: number | null;
}

export function liftOverBaseline(outcomes: readonly StrategyOutcome[]): LiftRow[] {
  const rate = (o: StrategyOutcome) => (o.episodes > 0 ? o.hits / o.episodes : 0);
  const base = outcomes.find(o => o.strategyId === BASELINE_ID);
  if (!base) throw new Error(`lift needs the baseline strategy ${BASELINE_ID} in the outcomes`);
  const baseRate = rate(base);
  return outcomes.map(o => ({ strategyId: o.strategyId, episodes: o.episodes, hits: o.hits, hitRate: rate(o), lift: rate(o) - baseRate, ratio: baseRate > 0 ? rate(o) / baseRate : null }));
}
