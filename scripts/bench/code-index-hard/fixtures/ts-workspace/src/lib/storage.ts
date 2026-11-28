import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { env } from "../config/env";

export const storage = {
  put(key: string, data: string): string {
    const target = join(env.uploadRoot, key);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, data);
    return key;
  },
  read(key: string): string {
    return readFileSync(join(env.uploadRoot, key), "utf8");
  },
};
