export class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

export const notFound = (what: string): HttpError => new HttpError(404, what + " not found");
export const badRequest = (message: string): HttpError => new HttpError(400, message);
export const forbidden = (message = "forbidden"): HttpError => new HttpError(403, message);
