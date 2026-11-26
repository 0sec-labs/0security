import { useState, type ReactNode } from "react";
import { CapyCopyIcon as Copy } from "@/ui/icons/capy";
import { Button } from "@/components/ui/button";
import { formatTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { FindingFixInfo, FindingFixRecord, FindingLocation } from "@/types";
import { checksLabel, locationText, parseDiff, pullRequestLabel, safePullRequestHref, type DiffLineKind } from "./finding-fix-model";

function SectionLabel({ children }: { children: ReactNode }) {
  return <h3 className="text-xs font-medium text-muted-foreground-1">{children}</h3>;
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [notice, setNotice] = useState<string | null>(null);
  const copy = async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard access is unavailable.");
      await navigator.clipboard.writeText(text);
      setNotice("Copied.");
    } catch { setNotice("Couldn't copy. Select the text and copy it manually."); }
  };
  return (
    <span className="flex items-center gap-2">
      {notice ? <span role="status" className="text-xs text-muted-foreground-1">{notice}</span> : null}
      <Button variant="outline" size="sm" aria-label={label} onClick={() => void copy()}><Copy className="size-4" />Copy</Button>
    </span>
  );
}

/** Where the finding was cited. Read-only: the server sends the stored citation and never opens the file. */
export function CodeLocationSection({ location }: { location: FindingLocation | null | undefined }) {
  if (!location) return null;
  const text = locationText(location);
  return (
    <section aria-label="Code location" className="flex max-w-4xl flex-col gap-2">
      <SectionLabel>Code location</SectionLabel>
      <div className="flex items-center justify-between gap-3 rounded-md border-[0.5px] border-border-1 bg-card px-3 py-2">
        <code className="min-w-0 break-all font-mono text-xs text-foreground">{text}</code>
        <CopyButton text={text} label={`Copy ${text}`} />
      </div>
      {location.suggestion ? (
        <div className="flex flex-col gap-1">
          <p className="text-xs text-muted-foreground-1">Suggested replacement from the scan</p>
          <pre tabIndex={0} aria-label="Suggested replacement" className="max-h-64 overflow-auto rounded-md bg-secondary px-3 py-2 font-mono text-xs leading-5 whitespace-pre text-foreground">{location.suggestion}</pre>
        </div>
      ) : null}
    </section>
  );
}

const LINE_CLASS: Record<DiffLineKind, string> = {
  add: "bg-success/10 text-foreground",
  remove: "bg-destructive/10 text-foreground",
  hunk: "text-muted-foreground-1",
  meta: "text-muted-foreground-2",
  context: "text-foreground",
};

function DiffView({ diff, truncated }: { diff: string; truncated: boolean }) {
  const lines = parseDiff(diff);
  return (
    <div className="flex flex-col gap-1">
      <pre tabIndex={0} aria-label="Fix diff" className="max-h-96 overflow-auto rounded-md border-[0.5px] border-border-1 bg-card py-2 font-mono text-xs leading-5">
        {lines.map((line, index) => <span key={index} className={cn("block min-w-max px-3 whitespace-pre", LINE_CLASS[line.kind])}>{line.text || " "}</span>)}
      </pre>
      {truncated ? <p className="text-xs text-muted-foreground-2">The diff is cut here. Open the branch to see the rest.</p> : null}
    </div>
  );
}

function FixRecord({ record }: { record: FindingFixRecord }) {
  const href = safePullRequestHref(record.pullRequestUrl);
  const when = Date.parse(record.recordedAt);
  return (
    <div className="flex flex-col gap-2 rounded-md border-[0.5px] border-border-1 bg-card px-3 py-2">
      <dl className="grid grid-cols-[104px_minmax(0,1fr)] gap-x-2 gap-y-1 text-[13px]">
        {record.branch ? <><dt className="text-xs text-muted-foreground-1">Branch</dt><dd className="min-w-0 break-all font-mono text-xs text-foreground">{record.branch}</dd></> : null}
        <dt className="text-xs text-muted-foreground-1">Pull request</dt>
        <dd className="min-w-0 text-foreground">
          {pullRequestLabel(record)}
          {href ? <>{" "}<a href={href} target="_blank" rel="noopener noreferrer" className="break-all text-primary underline underline-offset-2">{href}</a></> : null}
        </dd>
        <dt className="text-xs text-muted-foreground-1">Checks</dt>
        <dd className="text-foreground">{checksLabel(record)}</dd>
        {Number.isFinite(when) ? <><dt className="text-xs text-muted-foreground-1">Recorded</dt><dd className="text-muted-foreground-1">{formatTime(when)}</dd></> : null}
      </dl>
      {record.diff ? <DiffView diff={record.diff} truncated={record.diffTruncated === true} /> : record.branch ? <p className="text-xs text-muted-foreground-2">The diff is not available on this machine. The branch is gone or holds more than one commit.</p> : null}
    </div>
  );
}

/** The fix recorded by `findings fix`, or the command that makes one. Nothing here asks the code host. */
export function FixSection({ fix }: { fix: FindingFixInfo | undefined }) {
  if (!fix) return null;
  return (
    <section aria-label="Fix" className="flex max-w-4xl flex-col gap-2">
      <SectionLabel>Fix</SectionLabel>
      {fix.records.length ? fix.records.map((record, index) => <FixRecord key={`${record.branch}-${index}`} record={record} />) : (
        <div className="flex flex-col gap-2">
          <p className="text-[13px] text-muted-foreground-1">No fix recorded. Run this in the repository to propose one:</p>
          <div className="flex items-center justify-between gap-3 rounded-md bg-secondary px-3 py-2">
            <code className="min-w-0 overflow-x-auto font-mono text-xs text-foreground">{fix.command}</code>
            <CopyButton text={fix.command} label="Copy fix command" />
          </div>
        </div>
      )}
    </section>
  );
}
