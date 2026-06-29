import { describe, it, expect, beforeEach, vi } from "vitest";

// Stub the request factory (mirrors the reporter's approach: capture the SQL handed to the
// driver instead of running it). Shared state records every query() and input() across the
// multiple requests a single tool call makes (count / preview / final).
const h = vi.hoisted(() => {
  const state = {
    queries: [] as string[],
    inputs: [] as { name: string; value: unknown }[],
    count: 1,
  };
  const make = () => ({
    input(name: string, value: unknown) {
      state.inputs.push({ name, value });
      return this;
    },
    async query(sql: string) {
      state.queries.push(sql);
      return { recordset: [{ affectedRows: state.count }], rowsAffected: [state.count] };
    },
  });
  return { state, make };
});

vi.mock("../../src/transactions/TransactionManager.js", () => ({
  createRequest: () => h.make(),
}));

import { UpdateDataTool } from "../../src/tools/UpdateDataTool.js";
import { DeleteDataTool } from "../../src/tools/DeleteDataTool.js";
import { InsertDataTool } from "../../src/tools/InsertDataTool.js";
import { ExecuteTransactionTool } from "../../src/tools/ExecuteTransactionTool.js";

const MALICIOUS_TABLE = "Orders; DROP TABLE Users--";
const okFilters = [{ column: "status", operator: "=", value: "archived" }];

beforeEach(() => {
  h.state.queries.length = 0;
  h.state.inputs.length = 0;
  h.state.count = 1;
});

// WHY: the original CVE fired on the FIRST, unconfirmed call because the COUNT/preview queries
// ran before the confirmation gate. A malicious identifier must be rejected before ANY SQL
// reaches the driver — if this regresses, injection executes pre-confirmation again.
describe("update_data — injection is rejected before any query runs", () => {
  it("rejects a malicious tableName without touching the database", async () => {
    const res = await new UpdateDataTool().run({
      tableName: MALICIOUS_TABLE,
      updates: { status: "x" },
      filters: okFilters,
      confirmUpdate: false,
      pool: {},
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_REQUEST");
    expect(h.state.queries).toHaveLength(0); // nothing executed pre-confirmation
  });

  it("rejects a malicious update column name without touching the database", async () => {
    const res = await new UpdateDataTool().run({
      tableName: "Orders",
      updates: { "x] = 1; DROP TABLE Users--": "y" },
      filters: okFilters,
      pool: {},
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_REQUEST");
    expect(h.state.queries).toHaveLength(0);
  });

  it("rejects the removed free-form whereClause with a migration error", async () => {
    const res = await new UpdateDataTool().run({
      tableName: "Orders",
      updates: { status: "x" },
      whereClause: "1=1; DROP TABLE Users--",
      pool: {},
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("WHERECLAUSE_REMOVED");
    expect(h.state.queries).toHaveLength(0);
  });

  it("parameterizes a valid update and never interpolates the filter value", async () => {
    const res = await new UpdateDataTool().run({
      tableName: "dbo.Orders",
      updates: { status: "active" },
      filters: [{ column: "status", operator: "=", value: "archived" }],
      confirmUpdate: false,
      pool: {},
    });
    expect(res.needsConfirmation).toBe(true);
    const countSql = h.state.queries[0];
    expect(countSql).toContain("FROM [dbo].[Orders]");
    expect(countSql).toContain("WHERE [status] = @w_0");
    expect(countSql).not.toContain("archived"); // value is bound, not in the SQL text
    expect(h.state.inputs).toContainEqual({ name: "w_0", value: "archived" });
  });
});

// WHY: delete is the highest-blast-radius write; its identifier and filter must be neutralised
// before the pre-confirmation COUNT/preview queries run.
describe("delete_data — injection is rejected before any query runs", () => {
  it("rejects a malicious tableName without touching the database", async () => {
    const res = await new DeleteDataTool().run({
      tableName: MALICIOUS_TABLE,
      filters: okFilters,
      confirmDelete: false,
      pool: {},
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_REQUEST");
    expect(h.state.queries).toHaveLength(0);
  });

  it("rejects the removed free-form whereClause with a migration error", async () => {
    const res = await new DeleteDataTool().run({
      tableName: "Orders",
      whereClause: "1=1; DROP TABLE Users--",
      pool: {},
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("WHERECLAUSE_REMOVED");
    expect(h.state.queries).toHaveLength(0);
  });

  it("parameterizes a valid delete preview", async () => {
    const res = await new DeleteDataTool().run({
      tableName: "Orders",
      filters: [{ column: "id", operator: "IN", value: [1, 2] }],
      confirmDelete: false,
      pool: {},
    });
    expect(res.needsConfirmation).toBe(true);
    expect(h.state.queries[0]).toContain("FROM [Orders] WHERE [id] IN (@w_0, @w_1)");
    expect(h.state.inputs).toContainEqual({ name: "w_0", value: 1 });
    expect(h.state.inputs).toContainEqual({ name: "w_1", value: 2 });
  });
});

// WHY: insert injects attacker-controlled JSON keys as column names; an unquoted key was a sink.
describe("insert_data — identifier injection is rejected", () => {
  it("rejects a malicious tableName without touching the database", async () => {
    const res = await new InsertDataTool().run({ tableName: MALICIOUS_TABLE, data: { a: 1 }, pool: {} });
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_REQUEST");
    expect(h.state.queries).toHaveLength(0);
  });

  it("rejects a malicious column key without touching the database", async () => {
    const res = await new InsertDataTool().run({
      tableName: "Orders",
      data: { "a) VALUES (1); DROP TABLE Users--": 1 },
      pool: {},
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_REQUEST");
    expect(h.state.queries).toHaveLength(0);
  });

  it("quotes the table and columns and binds the values for a valid insert", async () => {
    const res = await new InsertDataTool().run({ tableName: "dbo.Orders", data: { name: "John", age: 30 }, pool: {} });
    expect(res.success).toBe(true);
    const insertSql = h.state.queries[0];
    expect(insertSql).toContain("INSERT INTO [dbo].[Orders] ([age], [name])"); // keys are sorted + quoted
    expect(insertSql).not.toContain("John");
    expect(h.state.inputs.map((i) => i.value)).toContain("John");
  });
});

// WHY: execute_transaction had the identical raw-interpolation sinks but was not in the original
// report. Its validation must reject the removed whereClause and demand structured filters before
// a transaction is ever opened.
// NOTE on assertions here: the createRequest mock does NOT intercept transaction.request() (the
// internal executors use a real sql.Transaction), so a query-count assertion would be vacuous.
// The error code is the discriminator instead — these errors are returned by validateOperation
// BEFORE `new sql.Transaction(pool)`/begin(), so `pool: {}` is never dereferenced. A reverted
// implementation would instead fail later as TRANSACTION_FAILED on the empty pool.
describe("execute_transaction — validation rejects injection before a transaction opens", () => {
  it("rejects a malicious tableName before opening the transaction", async () => {
    const res = await new ExecuteTransactionTool().run({
      pool: {},
      operations: [{ type: "delete", tableName: MALICIOUS_TABLE, filters: okFilters }],
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_REQUEST");
  });

  it("rejects an operation that still uses whereClause", async () => {
    const res = await new ExecuteTransactionTool().run({
      pool: {},
      operations: [{ type: "delete", tableName: "Orders", whereClause: "1=1; DROP TABLE Users--" }],
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("WHERECLAUSE_REMOVED");
  });

  it("rejects an update operation that is missing filters", async () => {
    const res = await new ExecuteTransactionTool().run({
      pool: {},
      operations: [{ type: "update", tableName: "Orders", updates: { a: 1 } }],
    });
    expect(res.success).toBe(false);
    expect(res.error).toBe("INVALID_OPERATION");
  });
});
