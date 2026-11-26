import { cn } from "@/lib/utils";
import { executedPocView } from "./finding-executed-poc";

/** Chip for a list row: Script matched, Script unmatched or Static only, with the full sentence on hover. */
export function ExecutedPocChip({ executedPoc }: { executedPoc: unknown }) {
  const view = executedPocView(executedPoc);
  if (!view) return null;
  return (
    <span
      data-executed-poc={view.outcome}
      title={view.line}
      className={cn("shrink-0 rounded-md border-[0.5px] px-1.5 py-px text-xs @max-2xl/list:hidden", view.outcome === "script-matched" ? "border-border-3 text-foreground" : "border-border-2 text-muted-foreground-1")}
    >{view.label}</span>
  );
}

/** Detail section: the outcome in words, then the run facts. Never implies a reproduction, and shows a result only with a complete container run record. */
export function ExecutedPocSection({ executedPoc }: { executedPoc: unknown }) {
  const view = executedPocView(executedPoc);
  if (!view) return null;
  return (
    <section aria-label="PoC execution" data-executed-poc={view.outcome} className="flex max-w-4xl flex-col gap-2">
      <h3 className="text-xs font-medium text-muted-foreground-1">PoC execution</h3>
      <p className="text-[13px] leading-6 text-muted-foreground-1"><span className="font-medium text-foreground">{view.label}.</span> {view.line}.</p>
      {view.facts.length ? <p className="text-xs leading-5 text-muted-foreground-1">{view.facts.join(" \u00b7 ")}</p> : null}
    </section>
  );
}
