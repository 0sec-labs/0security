import { execSync } from "node:child_process";

// Count the lines of a file with the system wc.
export function countLines(file) {
  const out = execSync(`wc -l < ${file}`, { encoding: "utf8" });
  return Number(out.trim());
}
