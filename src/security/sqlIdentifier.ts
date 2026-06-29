/**
 * SQL Server identifier validation and quoting.
 *
 * Identifiers (table / column / index / schema names) cannot be passed as bound
 * parameters in T-SQL, so they must be validated against a strict allowlist and
 * bracket-quoted. This is the identifier chokepoint for the write, DDL and
 * transaction tools. (The read tools — ProfileTableTool, ReadDataTool,
 * ListTableTool, DescribeTableTool — already bracket-escape their identifiers
 * with `]]`-doubling, which is itself break-out-safe; consolidating them onto
 * this helper is a tracked follow-up, not a security gap.) Values are never
 * handled here — they are bound as parameters (see whereFilter.ts).
 */

/** SQL Server `sysname` limit. */
const MAX_IDENTIFIER_LENGTH = 128;

/**
 * Characters permitted in an identifier *before* quoting. SQL Server regular
 * identifiers allow letters, digits and `_ @ # $`; bracket-quoted identifiers may
 * additionally contain spaces. We accept that conservative set and reject
 * everything else — notably `;`, quotes, comment sequences and stray brackets.
 * Names that legitimately contain `]` are not supported (fail-closed).
 */
const IDENTIFIER_ALLOWED = /^[A-Za-z0-9_@#$ ]+$/;

export class InvalidIdentifierError extends Error {
  constructor(raw: unknown, reason: string) {
    super(`Invalid SQL identifier ${JSON.stringify(raw)}: ${reason}`);
    this.name = "InvalidIdentifierError";
  }
}

/**
 * Validate a single identifier part and return it bracket-quoted. Accepts input
 * that is already bracketed (e.g. `[Orders]`) and re-quotes it safely. Throws
 * {@link InvalidIdentifierError} on anything that is not a well-formed identifier.
 */
export function quoteName(raw: unknown): string {
  if (typeof raw !== "string") {
    throw new InvalidIdentifierError(raw, "must be a string");
  }
  let name = raw.trim();

  // Strip one layer of surrounding brackets if present, un-doubling `]]`.
  if (name.length >= 2 && name.startsWith("[") && name.endsWith("]")) {
    name = name.slice(1, -1).replace(/]]/g, "]");
  }

  if (name.length === 0) {
    throw new InvalidIdentifierError(raw, "must not be empty");
  }
  if (name.length > MAX_IDENTIFIER_LENGTH) {
    throw new InvalidIdentifierError(raw, `exceeds ${MAX_IDENTIFIER_LENGTH} characters`);
  }
  if (!IDENTIFIER_ALLOWED.test(name)) {
    throw new InvalidIdentifierError(raw, "contains characters outside [A-Za-z0-9_@#$ and space]");
  }
  // The allowlist above already forbids `]`, so the doubling is a no-op today. It is kept
  // deliberately so quoteName stays break-out-safe if the allowlist is ever relaxed.
  return `[${name.replace(/]/g, "]]")}]`;
}

/**
 * Validate and quote a possibly schema/database-qualified name such as
 * `Orders`, `dbo.Orders`, or `[dbo].[Orders]`. Each dot-separated part is
 * validated and quoted independently. Splitting is bracket-aware so a dot inside
 * `[...]` does not split the name.
 */
export function quoteQualified(raw: unknown): string {
  if (typeof raw !== "string") {
    throw new InvalidIdentifierError(raw, "must be a string");
  }
  const parts = splitQualified(raw);
  if (parts.length === 0 || parts.length > 4) {
    throw new InvalidIdentifierError(raw, "must have between 1 and 4 dot-separated parts");
  }
  return parts.map(quoteName).join(".");
}

/**
 * Reject a free-form type/constraint spec (e.g. `NVARCHAR(255) NOT NULL`) that
 * contains statement-breaking sequences. This is NOT an identifier — it is
 * intentionally free-form admin-supplied DDL — so we only block the characters
 * that would let it escape the column definition into a new statement.
 */
export function assertSafeTypeSpec(raw: unknown): string {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    throw new InvalidIdentifierError(raw, "column type must be a non-empty string");
  }
  if (/;|--|\/\*|\*\//.test(raw)) {
    throw new InvalidIdentifierError(raw, "column type must not contain ';' or comment sequences");
  }
  return raw.trim();
}

/** Split on `.` while treating `[...]` as opaque (dots inside brackets do not split). */
function splitQualified(raw: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inBracket = false;
  for (const ch of raw) {
    if (ch === "[") {
      inBracket = true;
    } else if (ch === "]") {
      inBracket = false;
    }
    if (ch === "." && !inBracket) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts;
}
