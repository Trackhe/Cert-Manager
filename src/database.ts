import { Database } from 'bun:sqlite';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import {
  CONFIG_KEY_ACTIVE_CA_ID,
  DEFAULT_CA_NAME_MIGRATION,
  DEFAULT_COMMON_NAME_ROOT,
} from './constants.js';
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

  const oldKeyPath = `${dataDir}/ca-key.pem`;
  const oldCertPath = `${dataDir}/ca-cert.pem`;
  if (existsSync(oldKeyPath) && existsSync(oldCertPath)) {
    const hasAnyCa = database.prepare('SELECT 1 FROM cas LIMIT 1').get() != null;
    if (!hasAnyCa) {
      writeFileSync(paths.caKeyPath('default'), readFileSync(oldKeyPath, 'utf8'));
      writeFileSync(paths.caCertPath('default'), readFileSync(oldCertPath, 'utf8'));
      database.prepare(
        'INSERT OR IGNORE INTO cas (id, name, common_name, created_at) VALUES (?, ?, ?, datetime("now"))'
      ).run('default', DEFAULT_CA_NAME_MIGRATION, DEFAULT_COMMON_NAME_ROOT);
      database
        .prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`)
        .run(CONFIG_KEY_ACTIVE_CA_ID, 'default');
    }
  }

  ensureColumn(database, 'certificates', 'not_after', 'DATETIME');
  ensureColumn(database, 'certificates', 'pem', 'TEXT');
  ensureColumn(database, 'cas', 'not_after', 'DATETIME');
}
