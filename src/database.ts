import { Database } from 'bun:sqlite';
import type { PathHelpers } from './paths.js';

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    key_authorization TEXT NOT NULL,
    domain TEXT NOT NULL,
    expires_at DATETIME
  )`,
  `CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    not_after DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS acme_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    email TEXT,
    account_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS ca_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT UNIQUE NOT NULL,
    jwk TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS ca_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT UNIQUE NOT NULL,
    account_id TEXT NOT NULL,
    identifiers TEXT NOT NULL,
    status TEXT NOT NULL,
    finalize_url TEXT,
    cert_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS ca_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    authz_id TEXT UNIQUE NOT NULL,
    order_id TEXT NOT NULL,
    identifier TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS ca_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT UNIQUE NOT NULL,
    authz_id TEXT NOT NULL,
    type TEXT NOT NULL,
    token TEXT NOT NULL,
    key_authorization TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS ca_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT NOT NULL,
    pem TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS cas (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    common_name TEXT NOT NULL,
    not_after DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS intermediate_cas (
    id TEXT PRIMARY KEY,
    parent_ca_id TEXT NOT NULL,
    name TEXT NOT NULL,
    common_name TEXT NOT NULL,
    not_after DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS revoked_certificates (
    cert_id INTEGER PRIMARY KEY REFERENCES certificates(id),
    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS acme_whitelist_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
];

function ensureColumn(
  database: Database,
  tableName: string,
  columnName: string,
  columnDefinition: string
): void {
  const tableExists = database.prepare(
    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?"
  ).get(tableName);
  if (!tableExists) return;
  const columns = database.prepare(`PRAGMA table_info(${tableName})`).all() as Array<{ name: string }>;
  if (columns.some((column) => column.name === columnName)) return;
  database.run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDefinition}`);
}

export function createDatabase(dbPath: string): Database {
  return new Database(dbPath);
}

export function runMigrations(
  database: Database,
  dataDir: string,
  paths: PathHelpers
): void {
  for (const statement of SCHEMA_STATEMENTS) {
    database.run(statement);
  }

  ensureColumn(database, 'certificates', 'not_after', 'DATETIME');
  ensureColumn(database, 'certificates', 'pem', 'TEXT');
  ensureColumn(database, 'certificates', 'issuer_id', 'TEXT');
  ensureColumn(database, 'certificates', 'ca_certificate_id', 'INTEGER');
  ensureColumn(database, 'cas', 'not_after', 'DATETIME');
  ensureColumn(database, 'ca_challenges', 'accepted_at', 'INTEGER');
}
