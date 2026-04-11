import { parseSchemaPermissions } from "../utils/index.js";

/**
 * Permission checks read env vars dynamically on every call so that:
 *   1. Tests can change env vars between cases and see immediate effect.
 *   2. Runtime config changes (external control plane) take effect without restart.
 *
 * At startup, src/config/index.ts also reads these vars into cached consts used
 * for the startup log and the MCP tool description. That cache only affects the
 * initial log — the actual permission enforcement here is always live.
 *
 * Safety invariant: when no database is pinned (multi-DB mode), all writes are
 * blocked unless the operator explicitly opts in with MULTI_DB_WRITE_MODE=true.
 */

function isMultiDbModeNow(): boolean {
  const db = process.env.MYSQL_DB;
  return !db || db.trim() === "";
}

function multiDbBlocksWrites(): boolean {
  return isMultiDbModeNow() && process.env.MULTI_DB_WRITE_MODE !== "true";
}

function isGloballyAllowed(envVar: string): boolean {
  if (multiDbBlocksWrites()) return false;
  return process.env[envVar] === "true";
}

function isSchemaAllowed(
  schema: string | null,
  schemaEnvVar: string,
  globalEnvVar: string,
): boolean {
  const globally = isGloballyAllowed(globalEnvVar);
  if (!schema) return globally;
  const perms = parseSchemaPermissions(process.env[schemaEnvVar]);
  return schema in perms ? perms[schema] : globally;
}

function isInsertAllowedForSchema(schema: string | null): boolean {
  return isSchemaAllowed(
    schema,
    "SCHEMA_INSERT_PERMISSIONS",
    "ALLOW_INSERT_OPERATION",
  );
}

function isUpdateAllowedForSchema(schema: string | null): boolean {
  return isSchemaAllowed(
    schema,
    "SCHEMA_UPDATE_PERMISSIONS",
    "ALLOW_UPDATE_OPERATION",
  );
}

function isDeleteAllowedForSchema(schema: string | null): boolean {
  return isSchemaAllowed(
    schema,
    "SCHEMA_DELETE_PERMISSIONS",
    "ALLOW_DELETE_OPERATION",
  );
}

function isDDLAllowedForSchema(schema: string | null): boolean {
  return isSchemaAllowed(
    schema,
    "SCHEMA_DDL_PERMISSIONS",
    "ALLOW_DDL_OPERATION",
  );
}

export {
  isInsertAllowedForSchema,
  isUpdateAllowedForSchema,
  isDeleteAllowedForSchema,
  isDDLAllowedForSchema,
};
