import { readFileSync, existsSync } from "node:fs";
import { join, resolve, sep } from "node:path";

function inside(root, name) {
  const base = resolve(root);
  const file = resolve(base, name);
  if (file !== base && !file.startsWith(base + sep)) throw new Error("path escapes the uploads folder");
  return file;
}

// Serve a file a user uploaded earlier. `root` is the uploads folder.
export function readUpload(root, name) {
  return readFileSync(inside(root, name), "utf8");
}

export function hasUpload(root, name) {
  try { return existsSync(inside(root, name)); } catch { return false; }
}
