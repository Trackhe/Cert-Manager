import { Database } from 'bun:sqlite';
import type { PathHelpers } from './paths.js';

// Config-Schlüssel (für config-Tabelle) und Fallbacks in einem Ort
export const CONFIG_KEY_ACTIVE_CA_ID = 'active_ca_id';
export const CONFIG_KEY_ACTIVE_ACME_INTERMEDIATE_ID = 'active_acme_intermediate_id';
export const CONFIG_KEY_DEFAULT_COMMON_NAME_ROOT = 'default_common_name_root';
export const CONFIG_KEY_DEFAULT_COMMON_NAME_INTERMEDIATE = 'default_common_name_intermediate';
export const CONFIG_KEY_DEFAULT_KEY_SIZE = 'default_key_size';
export const CONFIG_KEY_DEFAULT_VALIDITY_YEARS = 'default_validity_years';
export const CONFIG_KEY_DEFAULT_VALIDITY_DAYS = 'default_validity_days';
export const CONFIG_KEY_DEFAULT_HASH_ALGORITHM = 'default_hash_algorithm';

const CONFIG_FALLBACKS: Record<string, string> = {
  [CONFIG_KEY_DEFAULT_COMMON_NAME_ROOT]: 'Meine CA',
  [CONFIG_KEY_DEFAULT_COMMON_NAME_INTERMEDIATE]: 'Intermediate CA',
  [CONFIG_KEY_DEFAULT_KEY_SIZE]: '2048',
  [CONFIG_KEY_DEFAULT_VALIDITY_YEARS]: '10',
  [CONFIG_KEY_DEFAULT_VALIDITY_DAYS]: '365',
  [CONFIG_KEY_DEFAULT_HASH_ALGORITHM]: 'sha256',
};

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
  `CREATE TABLE IF NOT EXISTS request_stats (
    date TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS acme_ca_domain_assignments (
    domain_pattern TEXT PRIMARY KEY,
    ca_id TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS cert_renewals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    renewed_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS log_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    line TEXT NOT NULL
  )`,
];

function ensureColumn(
  database: Database,
  tableName: string,
  columnName: string,
  columnDefinition: string
): void {
  const columns = database.prepare(`PRAGMA table_info(${tableName})`).all() as Array<{ name: string }>;
  if (columns.some((c) => c.name === columnName)) return;
  database.run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDefinition}`);
}

export function createDatabase(dbPath: string): Database {
  return new Database(dbPath);
}

/** Liest einen Config-Wert aus der DB, bei Fehlen Fallback aus CONFIG_FALLBACKS. */
export function getConfigValue(database: Database, key: string): string | null {
  const row = database.prepare('SELECT value FROM config WHERE key = ?').get(key) as { value: string } | undefined;
  return row?.value ?? CONFIG_FALLBACKS[key] ?? null;
}

/** Liest einen numerischen Config-Wert (z. B. key_size, validity_days). */
export function getConfigInt(database: Database, key: string): number {
  const s = getConfigValue(database, key);
  const n = s != null ? parseInt(s, 10) : NaN;
  const fallback = CONFIG_FALLBACKS[key];
  return Number.isNaN(n) && fallback != null ? parseInt(fallback, 10) : n;
}

const DEFAULT_CONFIG_SEED: Array<[string, string]> = Object.entries(CONFIG_FALLBACKS);

export function runMigrations(
  database: Database,
  _dataDir: string,
  _paths: PathHelpers
): void {
  for (const statement of SCHEMA_STATEMENTS) {
    database.run(statement);
  }

  ensureColumn(database, 'certificates', 'not_after', 'DATETIME');
  ensureColumn(database, 'certificates', 'pem', 'TEXT');
  ensureColumn(database, 'certificates', 'issuer_id', 'TEXT');
  ensureColumn(database, 'certificates', 'ca_certificate_id', 'INTEGER');
  ensureColumn(database, 'certificates', 'is_ev', 'INTEGER DEFAULT 0');
  ensureColumn(database, 'certificates', 'certificate_policy_oid', 'TEXT');
  ensureColumn(database, 'cas', 'not_after', 'DATETIME');
  ensureColumn(database, 'ca_challenges', 'accepted_at', 'INTEGER');

  const insertDefault = database.prepare('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)');
  for (const [key, value] of DEFAULT_CONFIG_SEED) {
    insertDefault.run(key, value);
  }
}
