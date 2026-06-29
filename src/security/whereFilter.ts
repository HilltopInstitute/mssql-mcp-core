/**
 * Structured WHERE-clause compiler.
 *
 * Replaces the former free-form `whereClause: string` parameter on the write
 * tools. Callers supply structured conditions; this module compiles them into a
 * parameterized predicate, binding every value via `request.input(...)` and
 * quoting every column identifier via {@link quoteName}. Values are NEVER
 * interpolated into SQL text, and operators are restricted to a fixed allowlist,
 * so a malicious value or operator cannot break out of the predicate.
 */
import type { Request } from "mssql";
import { quoteName } from "./sqlIdentifier.js";

export type FilterOperator =
  | "="
  | "<>"
  | "!="
  | "<"
  | "<="
  | ">"
  | ">="
  | "LIKE"
  | "IN"
  | "IS NULL"
  | "IS NOT NULL";

export interface FilterCondition {
  /** Column name — validated and quoted as an identifier. */
  column: string;
  /** Comparison operator — must be one of {@link FilterOperator}. */
  operator: FilterOperator;
  /** Bound as a parameter. Array for `IN`; omitted for `IS NULL` / `IS NOT NULL`. */
  value?: unknown;
}

export type MatchType = "all" | "any";

const VALUE_OPERATORS = new Set(["=", "<>", "!=", "<", "<=", ">", ">=", "LIKE"]);
const NO_VALUE_OPERATORS = new Set(["IS NULL", "IS NOT NULL"]);
const ALL_OPERATORS = new Set([...VALUE_OPERATORS, ...NO_VALUE_OPERATORS, "IN"]);

/** Human-readable allowlist for error messages. */
export const SUPPORTED_OPERATORS = [...ALL_OPERATORS];

export class InvalidFilterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidFilterError";
  }
}

/** The subset of `mssql.Request` this module needs — eases testing. */
type Bindable = Pick<Request, "input">;

/**
 * Compile structured filters into a parameterized WHERE-clause body (without the
 * leading `WHERE`) and bind all values onto `request`. At least one condition is
 * required, preserving the "writes must be scoped" safety guarantee.
 *
 * @param paramPrefix Prefix for generated parameter names (default `"w"`), kept
 *   distinct from a tool's value/SET parameters to avoid name collisions.
 * @throws {@link InvalidFilterError} on empty input, unknown operator, or value
 *   arity mismatch. May throw `InvalidIdentifierError` for a bad column name.
 */
export function buildWhereClause(
  request: Bindable,
  filters: unknown,
  matchType: MatchType = "all",
  paramPrefix = "w",
): string {
  if (!Array.isArray(filters) || filters.length === 0) {
    throw new InvalidFilterError(
      "At least one filter condition is required (e.g. { column: 'id', operator: '=', value: 1 }). " +
        "Free-form 'whereClause' strings are no longer accepted.",
    );
  }
  if (matchType !== "all" && matchType !== "any") {
    throw new InvalidFilterError(`matchType must be 'all' or 'any', got ${JSON.stringify(matchType)}.`);
  }

  const joiner = matchType === "any" ? " OR " : " AND ";
  let paramIndex = 0;

  const predicates = (filters as unknown[]).map((raw, i) => {
    if (!raw || typeof raw !== "object") {
      throw new InvalidFilterError(`Filter ${i} must be an object with 'column', 'operator', and (optionally) 'value'.`);
    }
    const cond = raw as Partial<FilterCondition>;
    const { operator } = cond;

    if (typeof operator !== "string" || !ALL_OPERATORS.has(operator)) {
      throw new InvalidFilterError(
        `Filter ${i}: unsupported operator ${JSON.stringify(operator)}. Allowed: ${SUPPORTED_OPERATORS.join(", ")}.`,
      );
    }

    const col = quoteName(cond.column); // throws InvalidIdentifierError on a bad column name

    if (NO_VALUE_OPERATORS.has(operator)) {
      return `${col} ${operator}`;
    }

    if (operator === "IN") {
      if (!Array.isArray(cond.value) || cond.value.length === 0) {
        throw new InvalidFilterError(`Filter ${i}: the IN operator requires a non-empty array value.`);
      }
      const placeholders = cond.value.map((v) => {
        const p = `${paramPrefix}_${paramIndex++}`;
        request.input(p, v);
        return `@${p}`;
      });
      return `${col} IN (${placeholders.join(", ")})`;
    }

    // Single-value operators (=, <>, !=, <, <=, >, >=, LIKE).
    if (cond.value === undefined) {
      throw new InvalidFilterError(`Filter ${i}: operator '${operator}' requires a value.`);
    }
    const p = `${paramPrefix}_${paramIndex++}`;
    request.input(p, cond.value);
    return `${col} ${operator} @${p}`;
  });

  return predicates.join(joiner);
}
