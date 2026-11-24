import type { AgentConfigFinding } from "./rules.js";
import { finding } from "./util.js";

/** Rule agent-config/injection-phrase. A heuristic: it matches wording and encoded blobs, so it is low severity and says so. */
const PHRASES: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|system|original)\s+(?:instructions?|prompts?|rules|directions?|guidelines)/i, label: "tells the agent to drop its earlier instructions" },
  { pattern: /\b(?:do\s+not|don['’]?t|never)\s+(?:tell|inform|mention|reveal|show|alert|notify)\s+(?:this\s+|that\s+|it\s+)?(?:to\s+)?the\s+user\b/i, label: "tells the agent to keep something from the user" },
  { pattern: /\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+user\b/i, label: "tells the agent to act without telling the user" },
  { pattern: /\b(?:hide|conceal)\s+(?:this|it|the\s+\w+)\s+from\s+the\s+user\b/i, label: "tells the agent to hide something from the user" },
];
const EXFIL = /\b(?:send|post|upload|exfiltrate|forward|transmit|email|curl|fetch)\b[^\n]{0,80}(?<![\w])(?:secrets?|tokens?|api[ _-]?keys?|credentials?|passwords?|ssh|\.env|environment variables?|conversation|chat history)(?![\w])[^\n]{0,80}https?:\/\/\S+|https?:\/\/\S+[^\n]{0,80}\b(?:send|post|upload|exfiltrate)\b[^\n]{0,40}(?<![\w])(?:secrets?|tokens?|api[ _-]?keys?|credentials?|\.env)(?![\w])/i;
const BASE64 = /[A-Za-z0-9+/]{200,}={0,2}/g;

/** Files whose purpose is to instruct an agent: visible instructions in them are what the author meant, so only hidden or encoded text is reported. */
export function isRulesFile(path: string): boolean {
  const p = path.toLowerCase();
  return /(?:^|\/)(?:claude|agents|gemini)\.md$/.test(p) || /(?:^|\/)\.cursorrules$/.test(p) || /(?:^|\/)\.cursor\/rules\//.test(p) || /(?:^|\/)\.github\/(?:copilot-instructions\.md|instructions\/)/.test(p) || /(?:^|\/)\.clinerules(?:\/|$)/.test(p) || /(?:^|\/)\.windsurf\/rules\//.test(p);
}

function printableShare(bytes: Buffer): number {
  let ok = 0;
  for (const byte of bytes) if ((byte >= 0x20 && byte < 0x7f) || byte === 10 || byte === 13 || byte === 9) ok++;
  return bytes.length ? ok / bytes.length : 0;
}

export function scanInjection(file: string, text: string): AgentConfigFinding[] {
  const found: AgentConfigFinding[] = [];
  const rules = isRulesFile(file);
  const lines = text.split(/\r\n|\r|\n/);
  const commentLines = new Set<number>();
  // Lines inside <!-- ... --> comments, found with indexOf so an unclosed or repeated marker cannot make the scan quadratic.
  const lineStarts: number[] = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const lineAt = (index: number): number => { let lo = 0, hi = lineStarts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (lineStarts[mid]! <= index) lo = mid; else hi = mid - 1; } return lo + 1; };
  for (let from = text.indexOf("<!--"); from >= 0; from = text.indexOf("<!--", from + 4)) {
    const close = text.indexOf("-->", from + 4);
    const end = close < 0 ? text.length : close;
    for (let n = lineAt(from); n <= lineAt(end) && commentLines.size < 20000; n++) commentLines.add(n);
    if (close < 0) break;
    from = close;
  }
  lines.forEach((content, index) => {
    const lineNo = index + 1;
    if (content.length > 2000) return;
    if (!rules || commentLines.has(lineNo)) {
      for (const { pattern, label } of PHRASES) if (pattern.test(content)) found.push(finding("agent-config/injection-phrase", file, lineNo, content.trim(), `Heuristic: this text ${label}${rules ? " and sits in an HTML comment" : ""}.`));
      if (EXFIL.test(content)) found.push(finding("agent-config/injection-phrase", file, lineNo, content.trim(), `Heuristic: this text asks to send something sensitive to a URL${rules ? " and sits in an HTML comment" : ""}.`));
    }
    for (const blob of content.matchAll(BASE64)) {
      if (/^[0-9a-fA-F]+$/.test(blob[0]) || /data:[\w/+.-]+;base64,\s*$/.test(content.slice(0, blob.index))) continue;
      let decoded: Buffer;
      try { decoded = Buffer.from(blob[0], "base64"); } catch { continue; }
      if (printableShare(decoded) < 0.9 || !/\s/.test(decoded.toString("latin1"))) continue;
      found.push(finding("agent-config/injection-phrase", file, lineNo, `${blob[0].slice(0, 24)}... (${blob[0].length} characters)`, `Heuristic: a base64 block of ${blob[0].length} characters that decodes to readable text. Agents can read and follow encoded text.`));
    }
  });
  return found;
}
