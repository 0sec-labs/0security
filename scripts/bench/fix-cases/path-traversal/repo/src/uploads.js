import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

// Serve a file a user uploaded earlier. `root` is the uploads folder.
export function readUpload(root, name) {
  const file = join(root, name);
  return readFileSync(file, "utf8");
}

export function hasUpload(root, name) {
  return existsSync(join(root, name));
}
