/** Sign-in failure with an HTTP status. `reason` is a short stable code for the audit log; `message` is safe to show the browser. */
export class TeamAuthError extends Error {
  constructor(message: string, public readonly statusCode = 401, public readonly reason?: string) { super(message); }
}
