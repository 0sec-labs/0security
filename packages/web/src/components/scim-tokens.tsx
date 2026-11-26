import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CapyCopyIcon as Copy, CapyPlusIcon as Plus } from "@/ui/icons/capy";
import { localControlFetch } from "@/api";
import { queryKeys } from "@/queries";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Feedback, QueryState } from "@/components/console-control/control-ui";
import { ConfirmDialog } from "@/ui/components/confirm-dialog";
import { errorText } from "@/lib/api-error";

type ScimToken = { id: string; name: string; createdAt: string; revokedAt: string | null; lastUsedAt: string | null };
type ScimTokenList = { tokens: ScimToken[]; unavailable: string | null };
type CreatedScimToken = { token: string; record: ScimToken };
const dateLabel = (value: string) => new Date(value).toLocaleDateString();
const panel = "rounded-[var(--radius-panel,16px)] border-[0.5px] border-[var(--card-hairline)] bg-card";

/**
 * Owner-only SCIM tokens for the team Members page: make one, list them, revoke one.
 * The token text lives only in this component's state. It is never put in the query cache, storage or a log.
 */
export function ScimTokens({ workspaceId }: { workspaceId?: string }) {
  const cache = useQueryClient();
  const queryKey = queryKeys.teamScimTokens(workspaceId ?? "team");
  const tokens = useQuery({
    queryKey,
    queryFn: async ({ signal }): Promise<ScimTokenList> => {
      const response = await localControlFetch("/api/team/scim-tokens", { signal });
      if (!response.ok) throw new Error("Could not load SCIM tokens.");
      return response.json() as Promise<ScimTokenList>;
    },
  });
  const [name, setName] = useState("");
  const [created, setCreated] = useState<CreatedScimToken | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<ScimToken | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const createdRef = useRef<HTMLElement>(null);
  const listRef = useRef<HTMLHeadingElement>(null);
  const baseUrl = `${window.location.origin}/scim/v2`;
  const unavailable = tokens.data?.unavailable ?? null;
  // After a token is made, move focus to it so a keyboard or screen reader user lands on the one-time secret.
  useEffect(() => { if (created) createdRef.current?.focus(); }, [created]);

  const createToken = async () => {
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await localControlFetch("/api/team/scim-tokens", { method: "POST", body: JSON.stringify({ name: name.trim() }) });
      if (!response.ok) {
        const failure = await response.json().catch(() => ({})) as { error?: string };
        throw new Error(response.status === 403 && failure.error ? failure.error : "Could not create this token. Check the name and try again.");
      }
      const result = await response.json() as CreatedScimToken;
      if (typeof result.token !== "string" || !result.record?.id) throw new Error("The token response was incomplete. Refresh the list before trying again.");
      setCreated(result); setName("");
      await cache.invalidateQueries({ queryKey });
    } catch (cause) { setError(errorText(cause, "Could not create this token.")); }
    finally { setBusy(false); }
  };
  const revokeToken = async () => {
    if (!pendingRevoke) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await localControlFetch(`/api/team/scim-tokens/${encodeURIComponent(pendingRevoke.id)}`, { method: "DELETE" });
      if (!response.ok) throw new Error("Could not revoke this token. Refresh the list and try again.");
      if (created?.record.id === pendingRevoke.id) setCreated(null);
      setPendingRevoke(null); setMessage(`Token "${pendingRevoke.name}" revoked.`);
      await cache.invalidateQueries({ queryKey });
      listRef.current?.focus();
    } catch (cause) { setError(errorText(cause, "Could not revoke this token.")); }
    finally { setBusy(false); }
  };
  const copyToken = async () => {
    if (!created) return;
    try { await navigator.clipboard.writeText(created.token); setError(""); setMessage("Token copied."); }
    catch { setError("Could not copy automatically. Select the token below and copy it."); }
  };

  return <section aria-labelledby="scim-heading" className="space-y-4 pt-2">
    <div className="space-y-1">
      <h2 id="scim-heading" className="text-base font-medium">SCIM provisioning</h2>
      <p className="text-sm text-muted-foreground">Your identity provider uses a token to create, update and disable accounts. Make one token for each provider.</p>
    </div>
    <div className={`${panel} space-y-1 p-4 text-sm`}>
      <p className="text-muted-foreground">SCIM base URL</p>
      <p className="break-all font-mono text-xs">{baseUrl}</p>
      <p className="text-xs text-muted-foreground">Paste this URL and the token into your identity provider. The token is the bearer token.</p>
    </div>
    <QueryState pending={tokens.isPending} error={tokens.error} retry={tokens.refetch} label="Loading SCIM tokens…" />
    {unavailable && <p className="text-sm text-muted-foreground" data-testid="scim-license-notice">{unavailable} Existing tokens can still be listed and revoked.</p>}
    {tokens.data && !unavailable && !created && <form className="flex flex-wrap items-end gap-3" onSubmit={event => { event.preventDefault(); void createToken(); }}>
      <label className="block min-w-48 flex-1 space-y-2 text-sm"><span>Token name</span><Input autoComplete="off" value={name} onChange={event => setName(event.target.value)} maxLength={80} required disabled={busy} placeholder="Okta" /></label>
      <Button type="submit" disabled={busy || !name.trim()}><Plus className="size-4" />{busy ? "Creating…" : "Create token"}</Button>
    </form>}
    {created && <section ref={createdRef} tabIndex={-1} aria-label="New SCIM token" className={`${panel} space-y-4 p-5 outline-none focus-visible:ring-2 focus-visible:ring-ring/40`}>
      <h3 className="break-words text-base font-medium">{created.record.name}</h3>
      <p role="alert" className="text-sm font-medium text-destructive">Copy this token now. It is shown once and you cannot see it again.</p>
      <label className="block space-y-2 text-sm"><span>SCIM token</span><Input aria-label="New SCIM token" value={created.token} readOnly autoComplete="off" spellCheck={false} data-1p-ignore data-lpignore="true" className="font-mono" onFocus={event => event.target.select()} /></label>
      <div className="flex flex-wrap gap-2"><Button onClick={() => void copyToken()}><Copy className="size-4" />Copy token</Button><Button variant="outline" onClick={() => { setCreated(null); setMessage(""); setError(""); listRef.current?.focus(); }}>Done</Button></div>
    </section>}
    {tokens.data && <div className="space-y-2">
      <h3 ref={listRef} tabIndex={-1} className="text-sm font-medium outline-none">Tokens</h3>
      <ul className={`divide-y-[0.5px] divide-[var(--card-hairline)] ${panel} px-4`}>
        {tokens.data.tokens.map(token => <li key={token.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0 space-y-1">
            <p className="break-words text-sm font-medium">{token.name}</p>
            <p className="text-xs text-muted-foreground">{token.revokedAt ? `Revoked ${dateLabel(token.revokedAt)}` : "Active"} · Created {dateLabel(token.createdAt)}{token.lastUsedAt ? ` · Last used ${dateLabel(token.lastUsedAt)}` : " · Never used"}</p>
          </div>
          {!token.revokedAt && <Button variant="outline" size="sm" disabled={busy} aria-label={`Revoke ${token.name}`} onClick={() => { setPendingRevoke(token); setError(""); setMessage(""); }}>Revoke</Button>}
        </li>)}
        {tokens.data.tokens.length === 0 && <li className="py-4 text-sm text-muted-foreground">No SCIM tokens yet.</li>}
      </ul>
    </div>}
    <Feedback error={error} message={message} />
    <ConfirmDialog open={pendingRevoke !== null} onOpenChange={open => { if (!open) setPendingRevoke(null); }} pending={busy} spinner destructive confirmLabel="Revoke token" title={pendingRevoke ? `Revoke "${pendingRevoke.name}"?` : "Revoke token"} description="The identity provider using this token stops provisioning right away. Accounts it already made stay. You can make a new token afterward." onConfirm={() => void revokeToken()} />
  </section>;
}
