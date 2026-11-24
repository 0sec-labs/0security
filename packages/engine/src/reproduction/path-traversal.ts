/**
 * The first reproduction class: path traversal on an HTTP route of a Node app.
 *
 * The recipe is built in. The model's proof supplies only one thing: the request path that shows the traversal. It is
 * never run as written. The harness swaps the file the payload names for a canary file it plants itself, so a hit
 * means the traversal reached a file outside the folder the app serves, and nothing else in the app was read.
 */
import { posix } from "node:path";
import type { ReproProof } from "../shared/reproduction.js";

export const PATH_TRAVERSAL_CLASS = "path-traversal-http";
export const DEFAULT_START = "node server.js";
export const DEFAULT_PORT = 3000;

export interface TraversalPlan {
  /** Request path with the traversal, aimed at the canary. */
  attackPath: string;
  /** The same request without the `../` run: the canary must not be served by it. */
  controlPath: string;
  canaryName: string;
}

export type PlanResult = { ok: true; plan: TraversalPlan } | { ok: false; reason: string };

const TRAVERSAL_RUN = /((?:\.\.\/)+)([^?&#]*)/;

/** Turn a proposed proof into the one request this class can replay, or say why it cannot. */
export function planPathTraversal(proof: ReproProof): PlanResult {
  const http = proof.steps.filter((s) => s.kind === "http");
  if (http.length !== 1) return { ok: false, reason: "needs-exactly-one-http-step" };
  const step = http[0]!;
  if (step.kind !== "http" || step.method !== "GET") return { ok: false, reason: "only-get-requests-are-supported" };
  if (/%2e|%2f|%5c|\\/i.test(step.path)) return { ok: false, reason: "encoded-payloads-are-not-supported" };
  const match = TRAVERSAL_RUN.exec(step.path);
  if (!match) return { ok: false, reason: "no-traversal-in-the-request" };
  if (!step.path.startsWith("/") || /[\s\0]/.test(step.path)) return { ok: false, reason: "unusable-request-path" };
  const ext = posix.extname(match[2]!);
  const canaryName = `0-canary${/^\.[A-Za-z0-9]{1,8}$/.test(ext) ? ext : ".txt"}`;
  return {
    ok: true,
    plan: {
      attackPath: step.path.replace(TRAVERSAL_RUN, `${match[1]}${canaryName}`),
      controlPath: step.path.replace(TRAVERSAL_RUN, canaryName),
      canaryName,
    },
  };
}

export interface ScriptInput {
  start: string;
  port: number;
  /** Random per run. Written into the canary file and looked for in the response. */
  token: string;
  /** Random per run. Only the client's result line carries it, so the app cannot forge one by printing. */
  nonce: string;
  plan: TraversalPlan;
}

const CLIENT = [
  'const http=require("http");',
  "const port=Number(process.env.PORT),token=process.env.TOKEN;",
  'const dec=(s)=>Buffer.from(s,"base64").toString();',
  "const get=(p)=>new Promise((done)=>{",
  'const q=http.request({host:"127.0.0.1",port,path:p,method:"GET",timeout:5000},(res)=>{',
  'let body="";res.setEncoding("utf8");',
  'res.on("data",(c)=>{if(body.length<65536)body+=c});',
  'res.on("end",()=>done({status:res.statusCode,hit:body.includes(token)}));});',
  'q.on("error",()=>done(null));q.on("timeout",()=>{q.destroy();done(null)});q.end();});',
  "(async()=>{",
  "let listening=false;",
  'for(let i=0;i<60;i++){if(await get("/")){listening=true;break}await new Promise((s)=>setTimeout(s,250))}',
  "const out={listening};",
  "if(listening){out.control=await get(dec(process.env.CTL_B64));out.attack=await get(dec(process.env.REQ_B64))}",
  'console.log(process.env.NONCE_LINE+" "+JSON.stringify(out));',
  "})();",
].join("");

const b64 = (text: string) => Buffer.from(text, "utf8").toString("base64");

/**
 * The shell script that runs inside the container, in its working folder. No value from the repository or the model
 * is interpolated as shell text: the request paths travel as base64, the token and nonce are hex.
 */
export function buildPathTraversalScript(input: ScriptInput): string {
  const { token, nonce, plan } = input;
  if (!/^[0-9a-f]{16,64}$/.test(token) || !/^[0-9a-f]{16,64}$/.test(nonce)) throw new Error("token and nonce must be hex");
  if (!/^0-canary\.[A-Za-z0-9]{1,8}$/.test(plan.canaryName)) throw new Error("unsafe canary name");
  if (!Number.isInteger(input.port) || input.port < 1024 || input.port > 65535) throw new Error("port out of range");
  return [
    "WORK=$(pwd)",
    'PARENT=$(dirname "$WORK")',
    `printf '%s\\n' '${token}' > "$WORK/${plan.canaryName}"`,
    `[ "$PARENT" != "$WORK" ] && printf '%s\\n' '${token}' > "$PARENT/${plan.canaryName}"`,
    'LOG=$(mktemp)',
    `( PORT=${input.port} ${input.start} ) > "$LOG" 2>&1 &`,
    "APP=$!",
    `PORT=${input.port} TOKEN='${token}' NONCE_LINE='0REPRO-${nonce}' REQ_B64='${b64(plan.attackPath)}' CTL_B64='${b64(plan.controlPath)}' node -e '${CLIENT}'`,
    'if kill -0 "$APP" 2>/dev/null; then echo "0ALIVE-' + nonce + ' 1"; else echo "0ALIVE-' + nonce + ' 0"; fi',
    'kill "$APP" 2>/dev/null',
    'echo "--- app log ---"',
    'tail -c 600 "$LOG"',
    "exit 0",
  ].join("\n");
}
