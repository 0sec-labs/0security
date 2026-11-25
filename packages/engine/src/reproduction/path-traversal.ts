/**
 * The first reproduction class: path traversal on an HTTP route of a Node app.
 *
 * The recipe is built in. The model's proof supplies only one thing: the request path that shows the traversal. It is
 * never run as written. The harness swaps the file the payload names for a canary file it plants itself.
 *
 * The canary is made fresh inside the container, after the app is up and answering. Its token and its random file name
 * exist nowhere before that: not in the command text, not in the app's environment, not on disk while the app starts.
 * So an app cannot print or read them without a request that names the file. The limit: an app built to lie can still
 * answer the request by reading the planted file wherever it is. A hit means the app as run returned the canary for
 * this request. It is an observation of the running app, not proof about the code.
 */
import { posix } from "node:path";
import type { ReproProof } from "../shared/reproduction.js";

export const PATH_TRAVERSAL_CLASS = "path-traversal-http";
export const DEFAULT_START = "node server.js";
export const DEFAULT_PORT = 3000;

/** Stands for the canary's random file name in the request templates. The client fills it in inside the container. */
export const CANARY_PLACEHOLDER = "@@CANARY@@";

export interface TraversalPlan {
  /** Request path with the traversal, aimed at the canary. Holds the placeholder, not a file name. */
  attackPath: string;
  /** The same request without the `../` run: the canary must not be served by it. */
  controlPath: string;
  /** Extension kept from the payload (for example `.txt`), so extension filters do not hide the canary. */
  canaryExt: string;
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
  const canaryExt = /^\.[A-Za-z0-9]{1,8}$/.test(ext) ? ext : ".txt";
  return {
    ok: true,
    plan: {
      attackPath: step.path.replace(TRAVERSAL_RUN, `${match[1]}${CANARY_PLACEHOLDER}`),
      controlPath: step.path.replace(TRAVERSAL_RUN, CANARY_PLACEHOLDER),
      canaryExt,
    },
  };
}

export interface ScriptInput {
  start: string;
  port: number;
  /** Random per run. Only the client's result line carries it, so the app cannot forge one by printing. */
  nonce: string;
  plan: TraversalPlan;
}

// Runs inside the container, in the app's folder. Single quotes are not allowed in this text: it sits in a shell string.
const CLIENT = [
  'const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto");',
  "const port=Number(process.env.PORT);",
  'const dec=(s)=>Buffer.from(s,"base64").toString();',
  "const get=(p,token,name)=>new Promise((done)=>{",
  'const q=http.request({host:"127.0.0.1",port,path:p,method:"GET",timeout:5000},(res)=>{',
  'let body="";res.setEncoding("utf8");',
  'res.on("data",(c)=>{if(body.length<65536)body+=c});',
  'res.on("end",()=>done({status:res.statusCode,hit:Boolean(token)&&body.includes(name+" "+token)}));});',
  'q.on("error",()=>done(null));q.on("timeout",()=>{q.destroy();done(null)});q.end();});',
  "(async()=>{",
  "let listening=false;",
  'for(let i=0;i<60;i++){if(await get("/")){listening=true;break}await new Promise((s)=>setTimeout(s,250))}',
  "const out={listening};",
  "if(listening){",
  'const token=crypto.randomBytes(16).toString("hex");',
  'const name="0-canary-"+crypto.randomBytes(8).toString("hex")+process.env.CANARY_EXT;',
  "const where=[process.cwd(),path.dirname(process.cwd())];",
  'const files=[...new Set(where)].map((d)=>path.join(d,name));',
  'for(const f of files){try{fs.writeFileSync(f,"canary "+name+" "+token+"\\n")}catch(e){}}',
  'const fill=(t)=>dec(t).split("@@CANARY@@").join(name);',
  "out.token=token;",
  "out.control=await get(fill(process.env.CTL_B64),token,name);",
  "out.attack=await get(fill(process.env.REQ_B64),token,name);",
  "for(const f of files){try{fs.unlinkSync(f)}catch(e){}}",
  "}",
  'console.log(process.env.NONCE_LINE+" "+JSON.stringify(out));',
  "})();",
].join("");

const b64 = (text: string) => Buffer.from(text, "utf8").toString("base64");

/**
 * The shell script that runs inside the container, in its working folder. No value from the repository or the model
 * is interpolated as shell text: the request templates travel as base64, the nonce is hex. It holds no canary secret.
 */
export function buildPathTraversalScript(input: ScriptInput): string {
  const { nonce, plan } = input;
  if (!/^[0-9a-f]{16,64}$/.test(nonce)) throw new Error("nonce must be hex");
  if (!/^\.[A-Za-z0-9]{1,8}$/.test(plan.canaryExt)) throw new Error("unsafe canary extension");
  if (!Number.isInteger(input.port) || input.port < 1024 || input.port > 65535) throw new Error("port out of range");
  return [
    'LOG=$(mktemp)',
    `( PORT=${input.port} ${input.start} ) > "$LOG" 2>&1 &`,
    "APP=$!",
    `PORT=${input.port} CANARY_EXT='${plan.canaryExt}' NONCE_LINE='0REPRO-${nonce}' REQ_B64='${b64(plan.attackPath)}' CTL_B64='${b64(plan.controlPath)}' node -e '${CLIENT}'`,
    'if kill -0 "$APP" 2>/dev/null; then echo "0ALIVE-' + nonce + ' 1"; else echo "0ALIVE-' + nonce + ' 0"; fi',
    'kill "$APP" 2>/dev/null',
    'echo "--- app log ---"',
    'tail -c 600 "$LOG"',
    "exit 0",
  ].join("\n");
}
