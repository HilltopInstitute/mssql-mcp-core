import { describe, it, expect } from "vitest";
import { quoteName, quoteQualified, assertSafeTypeSpec, InvalidIdentifierError } from "../../src/security/sqlIdentifier.js";

// WHY: identifiers cannot be parameterized, so quoteName is the only thing standing between
// an attacker-supplied table/column name and raw SQL. If it stops escaping or stops rejecting
// metacharacters, every write tool is injectable again (CVE root cause).
describe("quoteName", () => {
  it("wraps a plain identifier in brackets", () => {
    expect(quoteName("Orders")).toBe("[Orders]");
  });

  // test-guard: allow removing an incoherent placeholder test authored moments ago in this
  // same change (it asserted that quoteName("a]b") returns "", but that call throws). The
  // security property (rejecting `]`) is retained by the throw assertion below.
  it("rejects a name containing ] (fail-closed)", () => {
    // We do not support `]` in names; the safe choice is to reject, never to emit it raw and
    // risk a bracket break-out. The allowlist forbids `]`, so the name never reaches raw SQL.
    expect(() => quoteName("a]b")).toThrow(InvalidIdentifierError);
  });

  it("rejects a classic stacked-statement injection payload", () => {
    expect(() => quoteName("Orders; DROP TABLE Users--")).toThrow(InvalidIdentifierError);
  });

  it("rejects an empty / whitespace-only name", () => {
    expect(() => quoteName("   ")).toThrow(InvalidIdentifierError);
  });

  it("rejects a non-string", () => {
    expect(() => quoteName(undefined)).toThrow(InvalidIdentifierError);
    expect(() => quoteName(42 as unknown)).toThrow(InvalidIdentifierError);
  });

  it("rejects an over-length identifier (> 128)", () => {
    expect(() => quoteName("a".repeat(129))).toThrow(InvalidIdentifierError);
  });

  it("re-quotes an already-bracketed identifier safely", () => {
    expect(quoteName("[Order Details]")).toBe("[Order Details]");
  });
});

// WHY: schema-qualified targets (dbo.Orders) are common; the splitter must quote each part
// without letting a dot inside brackets — or an injected part — slip through unquoted.
describe("quoteQualified", () => {
  it("quotes each part of a schema-qualified name", () => {
    expect(quoteQualified("dbo.Orders")).toBe("[dbo].[Orders]");
  });

  it("accepts pre-bracketed qualified names", () => {
    expect(quoteQualified("[dbo].[Orders]")).toBe("[dbo].[Orders]");
  });

  it("rejects an injection hidden in the table part", () => {
    expect(() => quoteQualified("dbo.Orders;DROP TABLE x")).toThrow(InvalidIdentifierError);
  });

  it("rejects more than 4 parts", () => {
    expect(() => quoteQualified("a.b.c.d.e")).toThrow(InvalidIdentifierError);
  });
});

// WHY: a column TYPE in create_table is free-form admin DDL, but it must never carry a
// statement terminator or comment — that would turn one column def into multiple statements.
describe("assertSafeTypeSpec", () => {
  it("passes a normal type + constraint", () => {
    expect(assertSafeTypeSpec("NVARCHAR(255) NOT NULL")).toBe("NVARCHAR(255) NOT NULL");
  });

  it("rejects a type carrying a statement break", () => {
    expect(() => assertSafeTypeSpec("INT); DROP TABLE Users--")).toThrow(InvalidIdentifierError);
  });

  it("rejects a comment sequence", () => {
    expect(() => assertSafeTypeSpec("INT /* x */")).toThrow(InvalidIdentifierError);
  });
});
