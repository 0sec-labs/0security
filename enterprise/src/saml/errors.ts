// Licensed under the 0security Enterprise License. See enterprise/LICENSE.

/** Short, stable reason codes. They go to the audit log; the browser only sees a generic message. */
export type SamlFailure =
  | "xml-too-large" | "xml-unsafe" | "xml-dtd" | "xml-comment" | "weak-algorithm"
  | "bad-request" | "unknown-relay-state" | "pending-full"
  | "verification" | "assertion-invalid" | "metadata" | "config";

export class SamlError extends Error {
  constructor(readonly reason: SamlFailure, message: string, readonly statusCode = 401) {
    super(message);
    this.name = "SamlError";
  }
}
