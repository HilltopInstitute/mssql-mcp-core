import sql from "mssql";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { quoteQualified, InvalidIdentifierError } from "../security/sqlIdentifier.js";

export class DropTableTool implements Tool {
  [key: string]: any;
  name = "drop_table";
  description = "Drops a table from the MSSQL Database.";
  inputSchema = {
    type: "object",
    properties: {
      tableName: { type: "string", description: "Name of the table to drop" },
      environment: {
        type: "string",
        description: "Optional environment name to target.",
      },
    },
    required: ["tableName"],
  } as any;

  async run(params: any) {
    try {
      const { tableName } = params;
      // Validate and quote the identifier (supports schema-qualified names).
      let table: string;
      try {
        table = quoteQualified(tableName);
      } catch (e) {
        if (e instanceof InvalidIdentifierError) {
          return { success: false, message: e.message };
        }
        throw e;
      }
      const query = `DROP TABLE ${table}`;
      await new sql.Request(params.pool).query(query);
      return {
        success: true,
        message: `Table '${tableName}' dropped successfully.`
      };
    } catch (error) {
      console.error("Error dropping table:", error);
      return {
        success: false,
        message: `Failed to drop table: ${error}`
      };
    }
  }
}