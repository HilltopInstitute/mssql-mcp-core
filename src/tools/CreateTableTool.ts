import sql from "mssql";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { quoteName, quoteQualified, assertSafeTypeSpec, InvalidIdentifierError } from "../security/sqlIdentifier.js";

export class CreateTableTool implements Tool {
  [key: string]: any;
  name = "create_table";
  description = "Creates a new table in the MSSQL Database with the specified columns.";
  inputSchema = {
    type: "object",
    properties: {
      tableName: { type: "string", description: "Name of the table to create" },
      environment: {
        type: "string",
        description: "Optional environment name to target.",
      },
      columns: {
        type: "array",
        description: "Array of column definitions (e.g., [{ name: 'id', type: 'INT PRIMARY KEY' }, ...])",
        items: {
          type: "object",
          properties: {
            name: { type: "string", description: "Column name" },
            type: { type: "string", description: "SQL type and constraints (e.g., 'INT PRIMARY KEY', 'NVARCHAR(255) NOT NULL')" }
          },
          required: ["name", "type"]
        }
      }
    },
    required: ["tableName", "columns"],
  } as any;

  async run(params: any) {
    try {
      const { tableName, columns } = params;
      if (!Array.isArray(columns) || columns.length === 0) {
        throw new Error("'columns' must be a non-empty array");
      }
      // Quote table and column identifiers; column type is free-form admin DDL but
      // must not contain statement-breaking sequences.
      let table: string;
      let columnDefs: string;
      try {
        table = quoteQualified(tableName);
        columnDefs = columns.map((col: any) => `${quoteName(col.name)} ${assertSafeTypeSpec(col.type)}`).join(", ");
      } catch (e) {
        if (e instanceof InvalidIdentifierError) {
          return { success: false, message: e.message };
        }
        throw e;
      }
      const query = `CREATE TABLE ${table} (${columnDefs})`;
      await new sql.Request(params.pool).query(query);
      return {
        success: true,
        message: `Table '${tableName}' created successfully.`
      };
    } catch (error) {
      console.error("Error creating table:", error);
      return {
        success: false,
        message: `Failed to create table: ${error}`
      };
    }
  }
}
