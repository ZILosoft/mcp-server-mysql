import * as dotenv from "dotenv";
import * as fs from "fs";
import { SchemaPermissions } from "../types/index.js";
import { parseSchemaPermissions, parseMySQLConnectionString } from "../utils/index.js";

/**
 * Read and validate an SSL file (certificate, key, or CA) for SSL connections.
 * @param filePath - Path to the SSL file (PEM format)
 * @param label - Human-readable label for error messages (e.g. "CA certificate", "client certificate")
 * @returns Buffer containing the file data
 * @throws Error if file doesn't exist, is empty, or cannot be read
 */
function readSSLFile(filePath: string, label: string): Buffer {
  try {
    // Check if file exists and is readable
    if (!fs.existsSync(filePath)) {
      throw new Error(`SSL ${label} file not found: ${filePath}`);
    }

    // Read the file
    const data = fs.readFileSync(filePath);

    // Basic validation - check it's not empty
    if (data.length === 0) {
      throw new Error(`SSL ${label} file is empty: ${filePath}`);
    }

    return data;
  } catch (error) {
    if (error instanceof Error) {
      // Re-throw our custom errors as-is
      if (error.message.startsWith('SSL ')) {
        throw error;
      }
      // Wrap other errors (like permission denied)
      throw new Error(`Failed to read SSL ${label}: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Read and validate CA certificate file for SSL connections.
 * @param filePath - Path to the CA certificate file (PEM format)
 * @returns Buffer containing the certificate data
 * @throws Error if file doesn't exist, is empty, or cannot be read
 */
function readCACertificate(filePath: string): Buffer {
  return readSSLFile(filePath, 'CA certificate');
}

export const MCP_VERSION = "2.0.2";

// @INFO: Load environment variables from .env file
dotenv.config();

// @INFO: Parse connection string if provided
// Connection string takes precedence over individual environment variables
const connectionStringConfig = process.env.MYSQL_CONNECTION_STRING
  ? parseMySQLConnectionString(process.env.MYSQL_CONNECTION_STRING)
  : {};

// @INFO: Update the environment setup to ensure database is correctly set
if (process.env.NODE_ENV === "test" && !process.env.MYSQL_DB) {
  process.env.MYSQL_DB = "mcp_test_db"; // @INFO: Ensure we have a database name for tests
}

// Multi-DB mode safety: when no database is pinned, writes are blocked unless
// the operator explicitly opts in with MULTI_DB_WRITE_MODE=true.
const dbFromEnvOrConnStringEarly = connectionStringConfig.database || process.env.MYSQL_DB;
const isMultiDbModeEarly =
  !dbFromEnvOrConnStringEarly || dbFromEnvOrConnStringEarly.trim() === "";
const MULTI_DB_WRITE_MODE = process.env.MULTI_DB_WRITE_MODE === "true";
const multiDbBlocksWrites = isMultiDbModeEarly && !MULTI_DB_WRITE_MODE;

// Write operation flags (global defaults).
// In multi-DB mode without MULTI_DB_WRITE_MODE=true, all writes are force-disabled.
export const ALLOW_INSERT_OPERATION =
  !multiDbBlocksWrites && process.env.ALLOW_INSERT_OPERATION === "true";
export const ALLOW_UPDATE_OPERATION =
  !multiDbBlocksWrites && process.env.ALLOW_UPDATE_OPERATION === "true";
export const ALLOW_DELETE_OPERATION =
  !multiDbBlocksWrites && process.env.ALLOW_DELETE_OPERATION === "true";
export const ALLOW_DDL_OPERATION =
  !multiDbBlocksWrites && process.env.ALLOW_DDL_OPERATION === "true";

// Transaction mode control
export const MYSQL_DISABLE_READ_ONLY_TRANSACTIONS = 
  process.env.MYSQL_DISABLE_READ_ONLY_TRANSACTIONS === "true";

// Schema-specific permissions
export const SCHEMA_INSERT_PERMISSIONS: SchemaPermissions =
  parseSchemaPermissions(process.env.SCHEMA_INSERT_PERMISSIONS);
export const SCHEMA_UPDATE_PERMISSIONS: SchemaPermissions =
  parseSchemaPermissions(process.env.SCHEMA_UPDATE_PERMISSIONS);
export const SCHEMA_DELETE_PERMISSIONS: SchemaPermissions =
  parseSchemaPermissions(process.env.SCHEMA_DELETE_PERMISSIONS);
export const SCHEMA_DDL_PERMISSIONS: SchemaPermissions = parseSchemaPermissions(
  process.env.SCHEMA_DDL_PERMISSIONS,
);

// Remote MCP configuration
export const IS_REMOTE_MCP = process.env.IS_REMOTE_MCP === "true";
export const REMOTE_SECRET_KEY = process.env.REMOTE_SECRET_KEY || "";
export const PORT = process.env.PORT || 3000;

// Check if we're in multi-DB mode (no specific DB set)
export const isMultiDbMode = isMultiDbModeEarly;

// Auto-detect whether SSL should be enabled.
// Rules (in priority order):
//   1. Connection string explicitly configures SSL → respect it
//   2. MYSQL_SSL env var explicitly set → respect it
//   3. Unix socket connection → no SSL needed
//   4. IPv4/IPv6 loopback or localhost → no SSL needed
//   5. Any other host (remote) → enable SSL automatically
function shouldAutoEnableSSL(): boolean {
  if (connectionStringConfig.ssl !== undefined) {
    return connectionStringConfig.ssl;
  }
  if (process.env.MYSQL_SSL !== undefined) {
    return process.env.MYSQL_SSL === "true";
  }
  if (connectionStringConfig.socketPath || process.env.MYSQL_SOCKET_PATH) {
    return false;
  }
  const host = connectionStringConfig.host || process.env.MYSQL_HOST || "127.0.0.1";
  const localHosts = new Set([
    "localhost",
    "127.0.0.1",
    "::1",
    "0:0:0:0:0:0:0:1",
    "0.0.0.0",
    "[::1]",
  ]);
  return !localHosts.has(host.toLowerCase());
}

export const IS_SSL_ENABLED = shouldAutoEnableSSL();
// True when SSL was not explicitly configured but auto-detected as needed
export const IS_SSL_AUTO_DETECTED =
  process.env.MYSQL_SSL === undefined &&
  connectionStringConfig.ssl === undefined &&
  IS_SSL_ENABLED;

// Effective SSL CA path: connection string takes precedence, then env var
const effectiveSSLCA = connectionStringConfig.sslCA || process.env.MYSQL_SSL_CA;

// Skip SSL certificate verification.
// Two equivalent opt-outs (legacy MYSQL_SSL_REJECT_UNAUTHORIZED=false for backwards compat):
const SSL_SKIP_VERIFY =
  process.env.MYSQL_SSL_SKIP_VERIFY === "true" ||
  process.env.MYSQL_SSL_REJECT_UNAUTHORIZED === "false";

export const IS_SSL_SKIP_VERIFY = IS_SSL_ENABLED && SSL_SKIP_VERIFY;

// When SSL is active, the user MUST either provide a CA certificate for verification
// or explicitly opt out with MYSQL_SSL_SKIP_VERIFY=true. This prevents the footgun
// where auto-enabled SSL gives encryption without authentication (MITM vulnerable).
if (IS_SSL_ENABLED && !effectiveSSLCA && !SSL_SKIP_VERIFY) {
  throw new Error(
    "SSL is enabled but neither a CA certificate nor a skip-verify flag is set.\n" +
      "  - Provide MYSQL_SSL_CA=/path/to/ca.pem for secure verified connections, OR\n" +
      "  - Set MYSQL_SSL_SKIP_VERIFY=true to explicitly disable certificate verification\n" +
      "    (NOT recommended for production — vulnerable to MITM attacks).\n" +
      (IS_SSL_AUTO_DETECTED
        ? "SSL was auto-enabled because the host is not local. " +
          "Set MYSQL_SSL=false to connect without encryption (also not recommended)."
        : ""),
  );
}

export const mcpConfig = {
  server: {
    name: "@benborla29/mcp-server-mysql",
    version: MCP_VERSION,
    connectionTypes: ["stdio", "streamableHttp"],
  },
  mysql: {
    // Use Unix socket if provided (connection string takes precedence), otherwise use host/port
    ...(connectionStringConfig.socketPath || process.env.MYSQL_SOCKET_PATH
      ? {
          socketPath: connectionStringConfig.socketPath || process.env.MYSQL_SOCKET_PATH,
        }
      : {
          host: connectionStringConfig.host || process.env.MYSQL_HOST || "127.0.0.1",
          port: connectionStringConfig.port || Number(process.env.MYSQL_PORT || "3306"),
        }),
    user: connectionStringConfig.user || process.env.MYSQL_USER || "root",
    password:
      connectionStringConfig.password !== undefined
        ? connectionStringConfig.password
        : process.env.MYSQL_PASS === undefined
          ? ""
          : process.env.MYSQL_PASS,
    database: connectionStringConfig.database || process.env.MYSQL_DB || undefined, // Allow undefined database for multi-DB mode
    connectionLimit: 10,
    waitForConnections: true,
    queueLimit: process.env.MYSQL_QUEUE_LIMIT ? parseInt(process.env.MYSQL_QUEUE_LIMIT, 10) : 100,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
    connectTimeout: process.env.MYSQL_CONNECT_TIMEOUT ? parseInt(process.env.MYSQL_CONNECT_TIMEOUT, 10) : 10000,
    ...(IS_SSL_ENABLED
      ? {
          ssl: {
            // Default to strict verification. Only disable when user explicitly
            // opted out via MYSQL_SSL_SKIP_VERIFY=true (or legacy REJECT_UNAUTHORIZED=false).
            rejectUnauthorized: !SSL_SKIP_VERIFY,
            // Add CA certificate if provided (from connection string or env var)
            ...(effectiveSSLCA
              ? { ca: readCACertificate(effectiveSSLCA) }
              : {}),
            // Add client certificate for mTLS if provided
            ...(process.env.MYSQL_SSL_CERT
              ? { cert: readSSLFile(process.env.MYSQL_SSL_CERT, 'client certificate') }
              : {}),
            // Add client private key for mTLS if provided
            ...(process.env.MYSQL_SSL_KEY
              ? { key: readSSLFile(process.env.MYSQL_SSL_KEY, 'client private key') }
              : {}),
          },
        }
      : {}),
    // Timezone configuration for date/time handling
    ...(process.env.MYSQL_TIMEZONE
      ? {
          timezone: process.env.MYSQL_TIMEZONE,
        }
      : {}),
    // Return date values as strings instead of JavaScript Date objects
    ...(process.env.MYSQL_DATE_STRINGS === "true"
      ? {
          dateStrings: true,
        }
      : {}),
  },
  paths: {
    schema: "schema",
  },
};

export { readCACertificate, readSSLFile };
