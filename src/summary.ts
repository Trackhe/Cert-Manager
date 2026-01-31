import type { Database } from 'bun:sqlite';
import { existsSync } from 'node:fs';
import { getActiveCaId } from './ca.js';
import type { PathHelpers } from './paths.js';

export interface SummaryData {
  summary: {
    certsTotal: number;
    certsValid: number;
    timeUtc: string;
    timeLocal: string;
    letsEncrypt: { email: string; accountUrl: string } | null;
    caConfigured: boolean;
  };
  challenges: Array<{ token: string; domain: string; expires_at: string | null }>;
  certificates: Array<{
    id: number;
    domain: string;
    not_after: string | null;
    created_at: string | null;
    has_pem: number;
  }>;
  cas: Array<{
    id: string;
    name: string;
    commonName: string;
    notAfter: string | null;
    createdAt: string | null;
    isActive: boolean;
    isIntermediate: false;
  }>;
  intermediates: Array<{
    id: string;
    parentCaId: string;
    name: string;
    commonName: string;
    notAfter: string | null;
    createdAt: string | null;
    isIntermediate: true;
  }>;
}

export function getSummaryData(
  database: Database,
  paths: PathHelpers
): SummaryData {
  const now = new Date();

  const certCountRow = database.prepare('SELECT COUNT(*) as count FROM certificates').get() as { count: number };
  const validCountRow = database.prepare(
    "SELECT COUNT(*) as count FROM certificates WHERE not_after > datetime('now')"
  ).get() as { count: number };

  const accountRow = database.prepare(
    "SELECT provider, email, account_url FROM acme_accounts WHERE provider = 'letsencrypt' LIMIT 1"
  ).get() as { provider: string; email: string | null; account_url: string | null } | undefined;

  const challenges = database.prepare(
    'SELECT token, domain, expires_at FROM challenges ORDER BY id DESC'
  ).all() as Array<{ token: string; domain: string; expires_at: string | null }>;

  const certificates = database.prepare(
    'SELECT id, domain, not_after, created_at, (pem IS NOT NULL) as has_pem FROM certificates ORDER BY id DESC'
  ).all() as Array<{
    id: number;
    domain: string;
    not_after: string | null;
    created_at: string | null;
    has_pem: number;
  }>;

  const timeUtc = now.toISOString().slice(0, 19) + 'Z';
  const timeLocal = now.toLocaleString('de-DE', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  const activeCaId = getActiveCaId(database);
  const caConfigured =
    activeCaId != null &&
    existsSync(paths.caKeyPath(activeCaId)) &&
    existsSync(paths.caCertPath(activeCaId));

  const casRows = database.prepare(
    'SELECT id, name, common_name, not_after, created_at FROM cas ORDER BY created_at DESC'
  ).all() as Array<{
    id: string;
    name: string;
    common_name: string;
    not_after: string | null;
    created_at: string | null;
  }>;

  const cas = casRows.map((record) => ({
    id: record.id,
    name: record.name,
    commonName: record.common_name,
    notAfter: record.not_after,
    createdAt: record.created_at,
    isActive: record.id === activeCaId,
    isIntermediate: false as const,
  }));

  const intermediateRows = database.prepare(
    'SELECT id, parent_ca_id, name, common_name, not_after, created_at FROM intermediate_cas ORDER BY created_at DESC'
  ).all() as Array<{
    id: string;
    parent_ca_id: string;
    name: string;
    common_name: string;
    not_after: string | null;
    created_at: string | null;
  }>;

  const intermediates = intermediateRows.map((record) => ({
    id: record.id,
    parentCaId: record.parent_ca_id,
    name: record.name,
    commonName: record.common_name,
    notAfter: record.not_after,
    createdAt: record.created_at,
    isIntermediate: true as const,
  }));

  return {
    summary: {
      certsTotal: certCountRow.count,
      certsValid: validCountRow.count,
      timeUtc,
      timeLocal,
      letsEncrypt: accountRow
        ? { email: accountRow.email ?? '—', accountUrl: accountRow.account_url ?? '—' }
        : null,
      caConfigured,
    },
    challenges,
    certificates,
    cas,
    intermediates,
  };
}
