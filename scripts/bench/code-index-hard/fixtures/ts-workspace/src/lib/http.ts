export class HttpError extends Error {
  constructor(readonly status: number, message = "error") {
    super(message);
  }
}

export const notFound = () => new HttpError(404, "not found");
export const forbidden = () => new HttpError(403, "forbidden");
export const badRequest = (message = "bad request") => new HttpError(400, message);
