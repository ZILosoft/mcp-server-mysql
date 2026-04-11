import { log } from "./../utils/index.js";
import SqlParser, { AST } from "node-sql-parser";

const { Parser } = SqlParser;
const parser = new Parser();

// Extract schema from SQL query using AST parser for accuracy.
// Always parses the query to catch cross-database references even in single-DB mode:
// with MYSQL_DB=allowed_db, a query like `INSERT INTO forbidden_db.users` must return
// "forbidden_db" so permission checks see the real target, not the pinned default.
function extractSchemaFromQuery(sql: string): string | null {
  // Default schema from environment (fallback if query doesn't specify one)
  const defaultSchema = process.env.MYSQL_DB || null;

  try {
    const astOrArray: AST | AST[] = parser.astify(sql, { database: "mysql" });
    const statements = Array.isArray(astOrArray) ? astOrArray : [astOrArray];

    for (const stmt of statements) {
      // INSERT/UPDATE: target table has the primary schema
      if ("table" in stmt && stmt.table) {
        const tables = Array.isArray(stmt.table) ? stmt.table : [stmt.table];
        for (const t of tables) {
          if (t && typeof t === "object" && "db" in t && t.db) {
            return t.db as string;
          }
        }
      }
      // SELECT/DELETE: schema comes from FROM clause
      if ("from" in stmt && stmt.from) {
        const froms = Array.isArray(stmt.from) ? stmt.from : [stmt.from];
        for (const t of froms) {
          if (t && typeof t === "object" && "db" in t && t.db) {
            return t.db as string;
          }
        }
      }
    }
  } catch {
    // Fall back to regex on parse failure (e.g. USE statements, non-standard syntax)
    const useMatch = sql.match(/USE\s+`?([a-zA-Z0-9_]+)`?/i);
    if (useMatch?.[1]) return useMatch[1];
    const dbTableMatch = sql.match(/`?([a-zA-Z0-9_]+)`?\.`?[a-zA-Z0-9_]+`?/i);
    if (dbTableMatch?.[1]) return dbTableMatch[1];
  }

  return defaultSchema;
}

async function getQueryTypes(query: string): Promise<string[]> {
  try {
    log("info", "Parsing SQL query: ", query);
    // Parse into AST or array of ASTs - only specify the database type
    const astOrArray: AST | AST[] = parser.astify(query, { database: "mysql" });
    const statements = Array.isArray(astOrArray) ? astOrArray : [astOrArray];

    // Map each statement to its lowercased type (e.g., 'select', 'update', 'insert', 'delete', etc.)
    return statements.map((stmt) => stmt.type?.toLowerCase() ?? "unknown");
  } catch (err: any) {
    log("error", "sqlParser error, query: ", query);
    log("error", "Error parsing SQL query:", err);
    throw new Error(`Parsing failed: ${err.message}`);
  }
}

export { extractSchemaFromQuery, getQueryTypes };
