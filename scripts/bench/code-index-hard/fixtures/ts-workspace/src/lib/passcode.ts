import { createHash } from "node:crypto";

export const hashPasscode = (passcode: string) => createHash("sha256").update(`pc:${passcode}`).digest("hex");
