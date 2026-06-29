import { describe, it, expect } from "vitest";
import { ListDatabasesTool } from "../../src/tools/ListDatabasesTool.js";

// WHY: list_databases is a READER-tier tool that interpolates stateFilter straight into its SQL.
// The MCP inputSchema enum is not enforced at runtime, so without this allowlist a read-only
// client could inject stacked statements or UNION reads. If this regresses, the reader package
// (which is meant to be incapable of writes) becomes SQL-injectable. The check must run before
// any connection/query, so a bad value never reaches the database.
describe("list_databases - stateFilter is allowlisted before it reaches SQL", () => {
  const inject = (stateFilter: string) => new ListDatabasesTool().run({ stateFilter, pool: {} });

  it("rejects a stacked-statement payload", async () => {
    const res = await inject("ONLINE'; DROP TABLE dbo.Secrets; --");
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_PARAMETER");
  });

  it("rejects a UNION data-exfil payload", async () => {
    const res = await inject("x' UNION SELECT name,1,1,1,1,1,1,1,1 FROM sys.sql_logins--");
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_PARAMETER");
  });

  it("rejects any value outside the fixed set", async () => {
    const res = await inject("ONLINEX");
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_PARAMETER");
  });
});
