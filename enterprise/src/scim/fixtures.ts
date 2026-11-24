// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Examples copied from the RFCs, used by the tests. Only the texts the tests need are kept.
//   RFC 7643 section 8.1 (minimal user), 8.2 (full user, trimmed to the fields 0 reads), 8.4 (group).
//   RFC 7644 section 3.5.2.1 (add members, add attributes without a path), 3.5.2.2 (remove a member by filter,
//   with an add), 3.4.2 (query response) and 3.4.2.4 (ListResponse).
// Entra ID and Okta request shapes are from their SCIM documentation (see docs/src/content/docs/server-mode.md).

export const RFC7643_8_1_MINIMAL_USER = {
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
  id: "2819c223-7f76-453a-919d-413861904646",
  userName: "bjensen@example.com",
  meta: { resourceType: "User", created: "2010-01-23T04:56:22Z", lastModified: "2011-05-13T04:42:34Z", version: 'W/"3694e05e9dff590"', location: "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646" },
};

export const RFC7643_8_2_FULL_USER = {
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
  id: "2819c223-7f76-453a-919d-413861904646",
  externalId: "701984",
  userName: "bjensen@example.com",
  name: { formatted: "Ms. Barbara J Jensen, III", familyName: "Jensen", givenName: "Barbara", middleName: "Jane", honorificPrefix: "Ms.", honorificSuffix: "III" },
  displayName: "Babs Jensen",
  nickName: "Babs",
  emails: [{ value: "bjensen@example.com", type: "work", primary: true }, { value: "babs@jensen.org", type: "home" }],
  phoneNumbers: [{ value: "555-555-5555", type: "work" }, { value: "555-555-4444", type: "mobile" }],
  active: true,
};

export const RFC7643_8_4_GROUP = {
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  id: "e9e30dba-f08f-4109-8486-d5c6a331660a",
  displayName: "Tour Guides",
  members: [
    { value: "2819c223-7f76-453a-919d-413861904646", $ref: "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646", display: "Babs Jensen" },
    { value: "902c246b-6245-4190-8e05-00816be7344a", $ref: "https://example.com/v2/Users/902c246b-6245-4190-8e05-00816be7344a", display: "Mandy Pepperidge" },
  ],
};

const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/** RFC 7644 3.5.2.1: add a member to a group. */
export const RFC7644_ADD_MEMBER = {
  schemas: [PATCH],
  Operations: [{ op: "add", path: "members", value: [{ display: "Babs Jensen", $ref: "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646", value: "2819c223-7f76-453a-919d-413861904646" }] }],
};

/** RFC 7644 3.5.2.1: add attributes to a user without a path. */
export const RFC7644_ADD_WITHOUT_PATH = {
  schemas: [PATCH],
  Operations: [{ op: "add", value: { emails: [{ value: "babs@jensen.org", type: "home" }], nickname: "Babs" } }],
};

/** RFC 7644 3.5.2.2: remove a member by filter, then add another. */
export const RFC7644_REMOVE_AND_ADD_MEMBER = {
  schemas: [PATCH],
  Operations: [
    { op: "remove", path: 'members[value eq"2819c223-7f76-453a-919d-413861904646"]' },
    { op: "add", path: "members", value: [{ display: "James Smith", $ref: "https://example.com/v2/Users/08e1d05d-473d-93df-9210-000000000000", value: "08e1d05d-473d-93df-9210-000000000000" }] },
  ],
};

/** RFC 7644 3.4.2.4 shape of a paged ListResponse. */
export const RFC7644_LIST_RESPONSE_SHAPE = {
  totalResults: 100, itemsPerPage: 10, startIndex: 1, schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
};

/** Filter strings from RFC 7644 3.4.2.2 and from the identity provider documentation. */
export const FILTERS = {
  caseInsensitiveOperator: 'userName Eq "john"',
  caseInsensitiveAttribute: 'Username eq "john"',
  oktaUserLookup: 'userName eq "test.user@okta.local"',
  entraExternalId: 'externalId eq "jyoung"',
  entraGroupName: 'displayName eq "Test SCIMv2"',
  entraWorkEmail: 'emails[type eq "work"].value',
} as const;

/** Entra ID request shapes (docs: Tutorial: develop a SCIM endpoint for user provisioning). */
export const ENTRA = {
  disableUser: { Operations: [{ op: "Replace", path: "active", value: false }], schemas: [PATCH] },
  disableUserWithStringBoolean: { Operations: [{ op: "Replace", path: "active", value: "False" }], schemas: [PATCH] },
  addMember: { schemas: [PATCH], Operations: [{ op: "Add", path: "members", value: [{ $ref: null, value: "f648f8d5ea4e4cd38e9c" }] }] },
  removeMember: { schemas: [PATCH], Operations: [{ op: "Remove", path: "members", value: [{ $ref: null, value: "f648f8d5ea4e4cd38e9c" }] }] },
};

/** Okta request shapes (docs: SCIM 2.0 protocol, Okta Outbound SCIM). */
export const OKTA = {
  deactivateUser: { schemas: [PATCH], Operations: [{ op: "replace", value: { active: false } }] },
  removeThenAddMember: {
    schemas: [PATCH],
    Operations: [
      { op: "remove", path: 'members[value eq "89bb1940-b905-4575-9e7f-6f887cfb368e"]' },
      { op: "add", path: "members", value: [{ value: "23a35c27-23d3-4c03-b4c5-6443c09e7173", display: "test.user@okta.local" }] },
    ],
  },
  renameGroup: { schemas: [PATCH], Operations: [{ op: "replace", value: { id: "abf4dd94-a4c0-4f67-89c9-76b03340cb9b", displayName: "Test SCIMv2" } }] },
};
