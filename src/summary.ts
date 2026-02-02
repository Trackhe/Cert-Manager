import type { Database } from 'bun:sqlite';
import { existsSync } from 'node:fs';
import { getValidationStatus } from './acme-validation-state.js';
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
  challenges: Array<{ id: number; token: string; domain: string; expires_at: string | null }>;
  acmeChallenges: Array<{
    challengeId: string;
    token: string;
    domain: string;
    status: string;
    authzId: string;
    acceptedAt: number | null;
  }>;
  acmeValidationStatus: Array<{
    challengeId: string;
    domain: string;
    attemptCount: number;
    maxAttempts: number;
    nextAttemptAt: number;
  }>;
  certificates: Array<{
    id: number;
    domain: string;
    not_after: string | null;
    created_at: string | null;
    has_pem: number;
    issuer_id: string | null;
    revoked: number;
    ca_certificate_id: number | null;
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
  acmeWhitelistDomains: Array<{ id: number; domain: string; createdAt: string | null }>;
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
    'SELECT id, token, domain, expires_at FROM challenges ORDER BY id DESC'
  ).all() as Array<{ id: number; token: string; domain: string; expires_at: string | null }>;

  const acmeChallenges = database
    .prepare(
      `SELECT c.challenge_id AS challengeId, c.token, a.identifier AS domain, c.status, a.authz_id AS authzId, c.accepted_at AS acceptedAt
       FROM ca_challenges c
       JOIN ca_authorizations a ON a.authz_id = c.authz_id
       WHERE (a.status = 'pending' OR c.status = 'pending')
          OR (c.status = 'valid' AND c.accepted_at IS NOT NULL)
       ORDER BY c.id DESC`
    )
    .all() as Array<{
      challengeId: string;
      token: string;
      domain: string;
      status: string;
      authzId: string;
      acceptedAt: number | null;
    }>;

  const acmeValidationStatus = getValidationStatus();

  const acmeWhitelistDomains = database
    .prepare('SELECT id, domain, created_at AS createdAt FROM acme_whitelist_domains ORDER BY domain')
    .all() as Array<{ id: number; domain: string; createdAt: string | null }>;

  const certificates = database.prepare(
    `SELECT c.id, c.domain, c.not_after, c.created_at, (c.pem IS NOT NULL) as has_pem, c.issuer_id, c.ca_certificate_id,
            (SELECT 1 FROM revoked_certificates r WHERE r.cert_id = c.id) AS revoked
     FROM certificates c ORDER BY c.id DESC`
  ).all() as Array<{
    id: number;
    domain: string;
    not_after: string | null;
    created_at: string | null;
    has_pem: number;
    issuer_id: string | null;
    ca_certificate_id: number | null;
    revoked: number | null;
  }>;
  const certificatesNormalized = certificates.map((c) => ({
    ...c,
    revoked: c.revoked != null ? 1 : 0,
  }));

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
    acmeChallenges,
    acmeValidationStatus,
    certificates: certificatesNormalized,
    cas,
    intermediates,
    acmeWhitelistDomains,
  };
}
