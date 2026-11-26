import { z } from "zod";

/**
 * Spend limits of a Sentinel and of one of its triggers. A limit is a positive amount in USD. `null` or absent means no limit.
 * Days and months are UTC: a day starts at 00:00 UTC and a month on its first day at 00:00 UTC.
 */
export const BUDGET_MAX_USD = 100_000;
export const budgetCapSchema = z.number().positive().max(BUDGET_MAX_USD);

export type BudgetPeriod = "daily" | "monthly";
export interface BudgetCaps { dailyBudgetUsd?: number | null | undefined; monthlyBudgetUsd?: number | null | undefined }
export interface BudgetSpend { dayUsd: number; monthUsd: number }

/** Start of the UTC day that contains `ms`, as an ISO timestamp. */
export const utcDayStart = (ms: number): string => { const d = new Date(ms); d.setUTCHours(0, 0, 0, 0); return d.toISOString(); };
/** Start of the UTC month that contains `ms`, as an ISO timestamp. */
export const utcMonthStart = (ms: number): string => { const d = new Date(ms); d.setUTCHours(0, 0, 0, 0); d.setUTCDate(1); return d.toISOString(); };
const nextDayStart = (ms: number): string => new Date(Date.parse(utcDayStart(ms)) + 86_400_000).toISOString();
const nextMonthStart = (ms: number): string => { const d = new Date(utcMonthStart(ms)); d.setUTCMonth(d.getUTCMonth() + 1); return d.toISOString(); };

const usd = (n: number): string => `$${n.toFixed(n < 1 ? 4 : 2).replace(/(\.\d*?[1-9])0+$|\.0+$/, "$1")}`;

/**
 * Why a run may not start, or undefined when it may. A limit is reached when the spend so far is at or over it:
 * the cost of a run is not known before it starts. `subject` is "this Sentinel" or "this trigger".
 */
export function budgetRefusal(subject: "Sentinel" | "trigger", caps: BudgetCaps, spend: BudgetSpend, nowMs: number): string | undefined {
  const daily = caps.dailyBudgetUsd;
  if (typeof daily === "number" && spend.dayUsd >= daily) return `Budget reached: ${usd(spend.dayUsd)} of the ${usd(daily)} daily limit for this ${subject} is spent. It runs again at ${nextDayStart(nowMs).slice(0, 16).replace("T", " ")} UTC.`;
  const monthly = caps.monthlyBudgetUsd;
  if (typeof monthly === "number" && spend.monthUsd >= monthly) return `Budget reached: ${usd(spend.monthUsd)} of the ${usd(monthly)} monthly limit for this ${subject} is spent. It runs again at ${nextMonthStart(nowMs).slice(0, 16).replace("T", " ")} UTC.`;
  return undefined;
}
export const hasBudgetCap = (caps: BudgetCaps): boolean => typeof caps.dailyBudgetUsd === "number" || typeof caps.monthlyBudgetUsd === "number";
