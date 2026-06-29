import { describe, it, expect } from "vitest";
import { buildWhereClause, InvalidFilterError } from "../../src/security/whereFilter.js";
import { InvalidIdentifierError } from "../../src/security/sqlIdentifier.js";

/** Minimal stand-in for mssql.Request that records bound parameters. */
function fakeRequest() {
  const bound: Record<string, unknown> = {};
  const req = {
    bound,
    input(name: string, value: unknown) {
      bound[name] = value;
      return req as any;
    },
  };
  return req;
}

// WHY: buildWhereClause is the replacement for the injectable free-form whereClause. If it ever
// interpolates a value instead of binding it, or accepts an operator outside the allowlist, the
// WHERE clause becomes an injection vector again — the exact thing the CVE fix removes.
describe("buildWhereClause", () => {
  it("binds the value as a parameter and never interpolates it", () => {
    const req = fakeRequest();
    const clause = buildWhereClause(req, [{ column: "status", operator: "=", value: "archived" }]);
    expect(clause).toBe("[status] = @w_0");
    expect(req.bound).toEqual({ w_0: "archived" });
    expect(clause).not.toContain("archived");
  });

  it("keeps a SQL-injection payload confined to a bound parameter", () => {
    const req = fakeRequest();
    const payload = "x'; DROP TABLE Users--";
    const clause = buildWhereClause(req, [{ column: "name", operator: "=", value: payload }]);
    expect(clause).toBe("[name] = @w_0");
    expect(req.bound.w_0).toBe(payload); // the dangerous string is data, not SQL
    expect(clause).not.toContain("DROP");
  });

  it("requires at least one condition (writes must be scoped)", () => {
    expect(() => buildWhereClause(fakeRequest(), [])).toThrow(InvalidFilterError);
    expect(() => buildWhereClause(fakeRequest(), undefined)).toThrow(InvalidFilterError);
  });

  it("rejects an operator outside the allowlist", () => {
    expect(() =>
      buildWhereClause(fakeRequest(), [{ column: "x", operator: "; DROP" as any, value: 1 }]),
    ).toThrow(InvalidFilterError);
  });

  it("rejects a malicious column name via the identifier validator", () => {
    expect(() =>
      buildWhereClause(fakeRequest(), [{ column: "x = 1 OR 1=1--", operator: "=", value: 1 }]),
    ).toThrow(InvalidIdentifierError);
  });

  it("expands IN to one bound parameter per element", () => {
    const req = fakeRequest();
    const clause = buildWhereClause(req, [{ column: "id", operator: "IN", value: [1, 2, 3] }]);
    expect(clause).toBe("[id] IN (@w_0, @w_1, @w_2)");
    expect(req.bound).toEqual({ w_0: 1, w_1: 2, w_2: 3 });
  });

  it("rejects IN with a non-array / empty value", () => {
    expect(() => buildWhereClause(fakeRequest(), [{ column: "id", operator: "IN", value: 5 }])).toThrow(
      InvalidFilterError,
    );
    expect(() => buildWhereClause(fakeRequest(), [{ column: "id", operator: "IN", value: [] }])).toThrow(
      InvalidFilterError,
    );
  });

  it("emits IS NULL / IS NOT NULL with no bound value", () => {
    const req = fakeRequest();
    const clause = buildWhereClause(req, [{ column: "deleted_at", operator: "IS NULL" }]);
    expect(clause).toBe("[deleted_at] IS NULL");
    expect(req.bound).toEqual({});
  });

  it("rejects a value operator that is missing its value", () => {
    expect(() => buildWhereClause(fakeRequest(), [{ column: "x", operator: "=" }])).toThrow(InvalidFilterError);
  });

  it("joins multiple conditions with AND by default and OR for matchType 'any'", () => {
    const andClause = buildWhereClause(fakeRequest(), [
      { column: "a", operator: "=", value: 1 },
      { column: "b", operator: ">", value: 2 },
    ]);
    expect(andClause).toBe("[a] = @w_0 AND [b] > @w_1");

    const orClause = buildWhereClause(
      fakeRequest(),
      [
        { column: "a", operator: "=", value: 1 },
        { column: "b", operator: ">", value: 2 },
      ],
      "any",
    );
    expect(orClause).toBe("[a] = @w_0 OR [b] > @w_1");
  });
});
