import { readFileSync } from "node:fs";

// Count the lines of a file.
export function countLines(file) {
  const text = readFileSync(file, "utf8");
  return text.split("\n").length - (text.endsWith("\n") || text === "" ? 1 : 0);
}
