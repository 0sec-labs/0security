// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// SCIM message shapes (RFC 7643 and RFC 7644).
import { ScimError } from "./filter.js";

export const SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
export const SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
export const SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
export const SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
export const MAX_PAGE = 200;
export const DEFAULT_PAGE = 100;

export function errorBody(status: number, detail: string, scimType?: string) {
  return { schemas: [SCHEMA_ERROR], status: String(status), ...(scimType ? { scimType } : {}), detail };
}

export function errorFrom(error: unknown): { status: number; body: ReturnType<typeof errorBody> } {
  if (error instanceof ScimError) return { status: error.status, body: errorBody(error.status, error.message, error.scimType) };
  return { status: 500, body: errorBody(500, "The server could not process this request") };
}

/**
 * startIndex is 1-based (RFC 7644 section 3.4.2.4); a value below 1 means 1. A negative count means 0.
 * count is capped at MAX_PAGE. The server may return fewer resources than asked for.
 */
export function paginate<T>(all: readonly T[], query: { startIndex?: string | null; count?: string | null }): { schemas: string[]; totalResults: number; startIndex: number; itemsPerPage: number; Resources: T[] } {
  const startRaw = query.startIndex === null || query.startIndex === undefined || query.startIndex === "" ? 1 : Number(query.startIndex);
  const countRaw = query.count === null || query.count === undefined || query.count === "" ? DEFAULT_PAGE : Number(query.count);
  if (!Number.isInteger(startRaw) || !Number.isInteger(countRaw)) throw new ScimError(400, "invalidValue", "startIndex and count must be whole numbers");
  const startIndex = Math.max(1, startRaw);
  const count = Math.min(MAX_PAGE, Math.max(0, countRaw));
  const page = all.slice(startIndex - 1, startIndex - 1 + count);
  return { schemas: [SCHEMA_LIST], totalResults: all.length, startIndex, itemsPerPage: page.length, Resources: page };
}

export function serviceProviderConfig(documentationUri?: string) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    ...(documentationUri ? { documentationUri } : {}),
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: MAX_PAGE },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "A token created by a workspace owner, sent as Authorization: Bearer <token>" }],
  };
}

export function resourceTypes(base: string) {
  const type = (id: string, name: string, endpoint: string, schema: string) => ({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id, name, endpoint, schema, meta: { resourceType: "ResourceType", location: `${base}/ResourceTypes/${id}` },
  });
  return [type("User", "User", "/Users", SCHEMA_USER), type("Group", "Group", "/Groups", SCHEMA_GROUP)];
}

export function schemaDocuments(base: string) {
  const attr = (name: string, type = "string", extra: Record<string, unknown> = {}) => ({ name, type, multiValued: false, required: false, mutability: "readWrite", returned: "default", uniqueness: "none", ...extra });
  return [
    {
      id: SCHEMA_USER, name: "User", description: "A person who can sign in", meta: { resourceType: "Schema", location: `${base}/Schemas/${SCHEMA_USER}` },
      attributes: [
        attr("userName", "string", { required: true, uniqueness: "server" }), attr("externalId"), attr("displayName"),
        attr("name", "complex", { subAttributes: [attr("formatted"), attr("givenName"), attr("familyName")] }),
        attr("emails", "complex", { multiValued: true, subAttributes: [attr("value"), attr("type"), attr("primary", "boolean")] }),
        attr("active", "boolean"),
        attr("groups", "complex", { multiValued: true, mutability: "readOnly", subAttributes: [attr("value", "string", { mutability: "readOnly" }), attr("display", "string", { mutability: "readOnly" })] }),
      ],
    },
    {
      id: SCHEMA_GROUP, name: "Group", description: "A set of users", meta: { resourceType: "Schema", location: `${base}/Schemas/${SCHEMA_GROUP}` },
      attributes: [attr("displayName", "string", { required: true, uniqueness: "server" }), attr("externalId"), attr("members", "complex", { multiValued: true, subAttributes: [attr("value"), attr("display", "string", { mutability: "readOnly" })] })],
    },
  ];
}
