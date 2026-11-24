// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
import { describe, expect, it } from "vitest";
import { ENTRA, FILTERS, OKTA, RFC7643_8_1_MINIMAL_USER, RFC7643_8_2_FULL_USER, RFC7643_8_4_GROUP, RFC7644_ADD_MEMBER, RFC7644_ADD_WITHOUT_PATH, RFC7644_LIST_RESPONSE_SHAPE, RFC7644_REMOVE_AND_ADD_MEMBER } from "./fixtures.js";
import { ScimError, applyPatch, matchesFilter, paginate, parseFilter } from "./index.js";

const match = (filter: string, resource: unknown) => matchesFilter(parseFilter(filter), resource);

describe("filter", () => {
  it("matches eq on the RFC user, ignoring case of names, operators and values", () => {
    expect(match('userName eq "bjensen@example.com"', RFC7643_8_2_FULL_USER)).toBe(true);
    expect(match(FILTERS.caseInsensitiveOperator, { userName: "John" })).toBe(true);
    expect(match(FILTERS.caseInsensitiveAttribute, { userName: "john" })).toBe(true);
    expect(match('userName eq "other"', RFC7643_8_2_FULL_USER)).toBe(false);
    expect(match(FILTERS.entraExternalId, { externalId: "jyoung" })).toBe(true);
    expect(match(FILTERS.entraGroupName, { displayName: "Test SCIMv2" })).toBe(true);
  });

  it("supports the other operators, sub-attributes, value paths, and, or, not and brackets", () => {
    const user = RFC7643_8_2_FULL_USER;
    expect(match('userName sw "bjen"', user)).toBe(true);
    expect(match('userName ew "example.com"', user)).toBe(true);
    expect(match('userName co "jensen"', user)).toBe(true);
    expect(match('userName ne "x"', user)).toBe(true);
    expect(match("nickName pr", user)).toBe(true);
    expect(match("title pr", user)).toBe(false);
    expect(match('name.familyName eq "Jensen"', user)).toBe(true);
    expect(match('emails.value eq "babs@jensen.org"', user)).toBe(true);
    expect(match('emails[type eq "work" and primary eq true].value pr', user)).toBe(true);
    expect(match('emails[type eq "work"].value eq "bjensen@example.com"', user)).toBe(true);
    expect(match('emails[type eq "home"].value eq "bjensen@example.com"', user)).toBe(false);
    expect(match('active eq true and (userName eq "x" or externalId eq "701984")', user)).toBe(true);
    expect(match('not (userName eq "bjensen@example.com")', user)).toBe(false);
    expect(match('members[value eq "902c246b-6245-4190-8e05-00816be7344a"]', RFC7643_8_4_GROUP)).toBe(true);
    expect(match('members.value eq "nobody"', RFC7643_8_4_GROUP)).toBe(false);
  });

  it("refuses a filter it cannot read, with the SCIM error type", () => {
    for (const bad of ['userName', 'userName eq', 'userName eq "x', 'userName xx "x"', '(userName eq "x"', 'a eq 1 and', "x".repeat(3000)]) {
      expect(() => parseFilter(bad), bad.slice(0, 30)).toThrow(ScimError);
    }
    try { parseFilter("userName"); } catch (error) { expect(error).toMatchObject({ status: 400, scimType: "invalidFilter" }); }
  });
});

describe("pagination", () => {
  const all = Array.from({ length: 250 }, (_, i) => i + 1);
  it("is 1-based and reports the page", () => {
    expect(paginate(all, { startIndex: "1", count: "10" })).toMatchObject({ totalResults: 250, startIndex: 1, itemsPerPage: 10, schemas: RFC7644_LIST_RESPONSE_SHAPE.schemas });
    expect(paginate(all, { startIndex: "11", count: "5" }).Resources).toEqual([11, 12, 13, 14, 15]);
    expect(paginate(all, {}).itemsPerPage).toBe(100);
    expect(paginate(all, { count: "1000" }).itemsPerPage).toBe(200);
    expect(paginate(all, { count: "0" })).toMatchObject({ totalResults: 250, itemsPerPage: 0, Resources: [] });
    expect(paginate(all, { startIndex: "-5", count: "2" }).Resources).toEqual([1, 2]);
    expect(paginate(all, { startIndex: "300" })).toMatchObject({ itemsPerPage: 0, startIndex: 300 });
    expect(() => paginate(all, { count: "x" })).toThrow(ScimError);
  });
});

describe("patch: RFC 7644 examples", () => {
  it("adds a member to a group, and adding it again changes nothing", () => {
    const group = applyPatch(RFC7643_8_4_GROUP, RFC7644_ADD_MEMBER) as typeof RFC7643_8_4_GROUP;
    expect(group.members).toHaveLength(2);
    const added = applyPatch(RFC7643_8_4_GROUP, { ...RFC7644_ADD_MEMBER, Operations: [{ op: "add", path: "members", value: [{ value: "new-id" }] }] }) as typeof RFC7643_8_4_GROUP;
    expect(added.members.map((m) => m.value)).toContain("new-id");
    expect(applyPatch(added as never, { schemas: RFC7644_ADD_MEMBER.schemas, Operations: [{ op: "add", path: "members", value: [{ value: "new-id" }] }] }).members).toHaveLength(3);
  });

  it("adds attributes without a path: a new email and a new attribute", () => {
    const user = applyPatch(RFC7643_8_1_MINIMAL_USER, RFC7644_ADD_WITHOUT_PATH);
    expect(user.emails).toEqual([{ value: "babs@jensen.org", type: "home" }]);
    expect(user.nickname).toBe("Babs");
    const full = applyPatch(RFC7643_8_2_FULL_USER, RFC7644_ADD_WITHOUT_PATH);
    expect((full.emails as unknown[]).length).toBe(2); // babs@jensen.org is already there
  });

  it("removes a member by value filter and adds another, in order", () => {
    const group = applyPatch(RFC7643_8_4_GROUP, RFC7644_REMOVE_AND_ADD_MEMBER) as typeof RFC7643_8_4_GROUP;
    expect(group.members.map((m) => m.value)).toEqual(["902c246b-6245-4190-8e05-00816be7344a", "08e1d05d-473d-93df-9210-000000000000"]);
  });

  it("replaces single and multi-valued attributes, and removes by path", () => {
    const user = applyPatch(RFC7643_8_2_FULL_USER, { Operations: [
      { op: "replace", path: "displayName", value: "B. Jensen" },
      { op: "replace", path: "name.givenName", value: "Bea" },
      { op: "replace", path: 'emails[type eq "work"].value', value: "bea@example.com" },
      { op: "remove", path: "nickName" },
      { op: "remove", path: 'emails[type eq "home"]' },
    ] });
    expect(user).toMatchObject({ displayName: "B. Jensen", name: { givenName: "Bea", familyName: "Jensen" }, emails: [{ value: "bea@example.com", type: "work", primary: true }] });
    expect(user).not.toHaveProperty("nickName");
    expect(applyPatch(RFC7643_8_2_FULL_USER, { Operations: [{ op: "replace", path: "urn:ietf:params:scim:schemas:core:2.0:User:userName", value: "new@example.com" }] }).userName).toBe("new@example.com");
  });

  it("does not change the input and refuses bad requests", () => {
    const before = JSON.stringify(RFC7643_8_4_GROUP);
    applyPatch(RFC7643_8_4_GROUP, RFC7644_REMOVE_AND_ADD_MEMBER);
    expect(JSON.stringify(RFC7643_8_4_GROUP)).toBe(before);
    for (const bad of [null, [], {}, { Operations: [] }, { Operations: [{ op: "move", path: "a" }] }, { Operations: [{ op: "remove" }] }, { Operations: [{ op: "replace", value: "x" }] }, { schemas: ["x"], Operations: [{ op: "add", path: "a", value: 1 }] }, { Operations: [{ op: "add", path: "a b", value: 1 }] }, { Operations: [{ op: "replace", path: 'members[value eq "nobody"]', value: {} }] }]) {
      expect(() => applyPatch(RFC7643_8_4_GROUP, bad as never), JSON.stringify(bad)).toThrow(ScimError);
    }
    expect(() => applyPatch(RFC7643_8_4_GROUP, { Operations: Array.from({ length: 101 }, () => ({ op: "add", path: "a", value: 1 })) })).toThrow("At most");
  });
});

describe("patch: identity provider shapes", () => {
  const user = { ...RFC7643_8_2_FULL_USER };
  it("Entra: capitalised op names, active as a boolean or as a string", () => {
    expect(applyPatch(user, ENTRA.disableUser, { booleanAttributes: ["active"] }).active).toBe(false);
    expect(applyPatch(user, ENTRA.disableUserWithStringBoolean, { booleanAttributes: ["active"] }).active).toBe(false);
    expect(() => applyPatch(user, { Operations: [{ op: "Replace", path: "active", value: "maybe" }] }, { booleanAttributes: ["active"] })).toThrow("true or false");
  });

  it("Entra: add and remove members with the members as the value", () => {
    const added = applyPatch({ ...RFC7643_8_4_GROUP, members: [] }, ENTRA.addMember);
    expect(added.members).toEqual([{ $ref: null, value: "f648f8d5ea4e4cd38e9c" }]);
    expect(applyPatch(added, ENTRA.removeMember).members).toEqual([]);
  });

  it("Okta: replace without a path and an object value, remove then add a member, rename a group", () => {
    expect(applyPatch(user, OKTA.deactivateUser, { booleanAttributes: ["active"] }).active).toBe(false);
    const group = applyPatch({ ...RFC7643_8_4_GROUP, members: [{ value: "89bb1940-b905-4575-9e7f-6f887cfb368e" }] }, OKTA.removeThenAddMember) as { members: Array<{ value: string }> };
    expect(group.members.map((m) => m.value)).toEqual(["23a35c27-23d3-4c03-b4c5-6443c09e7173"]);
    expect(applyPatch(RFC7643_8_4_GROUP, OKTA.renameGroup).displayName).toBe("Test SCIMv2");
  });
});
