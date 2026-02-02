import * as crypto from 'node:crypto';
import type { Database } from 'bun:sqlite';
import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import {
  createRootCa,
  createIntermediateCa,
  getActiveCaId,
} from './ca.js';
import {
  CONFIG_KEY_ACTIVE_CA_ID,
  DEFAULT_COMMON_NAME_INTERMEDIATE,
  DEFAULT_COMMON_NAME_ROOT,
} from './constants.js';
import { createLeafCertificate } from './leaf-certificate.js';
import { getSummaryData } from './summary.js';
import type { PathHelpers } from './paths.js';

type ApiContext = {
  database: Database;
  paths: PathHelpers;
  request: Request;
  url: URL;
};

const { X509Certificate } = crypto;

export type CertInfoParsed = {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  fingerprint256: string;
  subjectAltName: string | null;
};

function parseCertInfo(pem: string): CertInfoParsed | null {
  try {
    const x = new X509Certificate(pem);
    const san = typeof (x as unknown as { subjectAltName?: string }).subjectAltName === 'string'
      ? (x as unknown as { subjectAltName: string }).subjectAltName
      : null;
    return {
      subject: x.subject,
      issuer: x.issuer,
      serialNumber: x.serialNumber,
      notBefore: x.validFrom,
      notAfter: x.validTo,
      fingerprint256: x.fingerprint256,
      subjectAltName: san ?? null,
    };
  } catch {
    return null;
  }
}

function slugFromName(name: string): string {
  return (
    name
      .toLowerCase()
      .trim()
      .replace(/\s+/g, '-')
      .replace(/[^a-z0-9-]/g, '') || 'ca-' + crypto.randomBytes(4).toString('hex')
  );
}

function createSseStream(
  database: Database,
  paths: PathHelpers,
  abortSignal?: AbortSignal
): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      const send = () => {
        try {
          const data = getSummaryData(database, paths);
          controller.enqueue(
            new TextEncoder().encode('data: ' + JSON.stringify(data) + '\n\n')
          );
        } catch {
          // ignore
        }
      };
      let intervalId: ReturnType<typeof setInterval>;
      const run = () => {
        send();
        intervalId = setInterval(send, 1000);
      };
      const millisecondsUntilNextSecond = 1000 - (Date.now() % 1000);
      const timeoutId = setTimeout(run, millisecondsUntilNextSecond);
      const onAbort = () => {
        clearTimeout(timeoutId);
        clearInterval(intervalId);
        controller.close();
      };
      abortSignal?.addEventListener('abort', onAbort);
    },
  });
}

async function handleEvents(context: ApiContext): Promise<Response> {
  const { database, paths, request } = context;
  return new Response(createSseStream(database, paths, request.signal), {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    },
  });
}

async function handleCaCert(context: ApiContext): Promise<Response> {
  const { database, paths, url } = context;
  const caId = url.searchParams.get('id') ?? getActiveCaId(database);
  if (!caId) return new Response('CA nicht gefunden', { status: 404 });
  const isIntermediate = database
    .prepare('SELECT 1 FROM intermediate_cas WHERE id = ?')
    .get(caId);
  const certPath = isIntermediate
    ? paths.intermediateCertPath(caId)
    : paths.caCertPath(caId);
  if (!existsSync(certPath)) return new Response('CA nicht gefunden', { status: 404 });
  const certificatePem = readFileSync(certPath, 'utf8');
  const filenamePrefix = isIntermediate ? 'intermediate-' : 'ca-';
  return new Response(certificatePem, {
    headers: {
      'Content-Type': 'application/x-pem-file',
      'Content-Disposition': `attachment; filename="${filenamePrefix}${caId}.pem"`,
    },
  });
}

async function handleCaSetup(context: ApiContext): Promise<Response> {
  const { database, paths, request } = context;
  try {
    const body = (await request.json()) as {
      name?: string;
      commonName?: string;
      organization?: string;
      organizationalUnit?: string;
      country?: string;
      locality?: string;
      stateOrProvince?: string;
      email?: string;
      validityYears?: number;
      keySize?: number;
      hashAlgo?: string;
    };
    const name = (body.name ?? body.commonName ?? DEFAULT_COMMON_NAME_ROOT).trim();
    const commonName = (body.commonName ?? name).trim();
    const slug = slugFromName(name);
    const existingCa = database.prepare('SELECT 1 FROM cas WHERE id = ?').get(slug);
    const finalCaId = existingCa ? slug + '-' + Date.now().toString(36) : slug;
    createRootCa(database, paths, finalCaId, {
      name: name || commonName,
      commonName: commonName || DEFAULT_COMMON_NAME_ROOT,
      organization: body.organization,
      organizationalUnit: body.organizationalUnit,
      country: body.country,
      locality: body.locality,
      stateOrProvince: body.stateOrProvince,
      email: body.email,
      validityYears: body.validityYears,
      keySize: body.keySize,
      hashAlgorithm: body.hashAlgo,
    });
    return Response.json({ ok: true, id: finalCaId });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('CA setup error:', message);
    return Response.json({ error: message }, { status: 400 });
  }
}

async function handleCaActivate(context: ApiContext): Promise<Response> {
  const { database, paths, request } = context;
  const body = (await request.json()) as { id: string };
  const caId = body.id;
  if (!caId) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const caRow = database.prepare('SELECT 1 FROM cas WHERE id = ?').get(caId);
  if (!caRow) return Response.json({ error: 'CA nicht gefunden' }, { status: 404 });
  if (!existsSync(paths.caCertPath(caId))) {
    return Response.json({ error: 'CA-Datei nicht gefunden' }, { status: 404 });
  }
  database
    .prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`)
    .run(CONFIG_KEY_ACTIVE_CA_ID, caId);
  return Response.json({ ok: true });
}

async function handleCaIntermediate(context: ApiContext): Promise<Response> {
  const { database, paths, request } = context;
  try {
    const body = (await request.json()) as {
      parentCaId?: string;
      name?: string;
      commonName?: string;
      organization?: string;
      organizationalUnit?: string;
      country?: string;
      locality?: string;
      stateOrProvince?: string;
      email?: string;
      validityYears?: number;
      keySize?: number;
      hashAlgo?: string;
    };
    const parentCaId = (body.parentCaId ?? '').trim();
    if (!parentCaId) {
      return Response.json({ error: 'parentCaId fehlt' }, { status: 400 });
    }
    const parentRow = database.prepare('SELECT 1 FROM cas WHERE id = ?').get(parentCaId);
    if (!parentRow) {
      return Response.json({ error: 'Parent-CA nicht gefunden' }, { status: 404 });
    }
    const name = (body.name ?? body.commonName ?? DEFAULT_COMMON_NAME_INTERMEDIATE).trim();
    const commonName = (body.commonName ?? name).trim();
    const slug = slugFromName(name);
    const existingIntermediate = database
      .prepare('SELECT 1 FROM intermediate_cas WHERE id = ?')
      .get(slug);
    const finalIntermediateId = existingIntermediate
      ? slug + '-' + Date.now().toString(36)
      : slug;
    createIntermediateCa(database, paths, parentCaId, finalIntermediateId, {
      name: name || commonName,
      commonName: commonName || DEFAULT_COMMON_NAME_INTERMEDIATE,
      organization: body.organization,
      organizationalUnit: body.organizationalUnit,
      country: body.country,
      locality: body.locality,
      stateOrProvince: body.stateOrProvince,
      email: body.email,
      validityYears: body.validityYears,
      keySize: body.keySize,
      hashAlgorithm: body.hashAlgo,
    });
    return Response.json({ ok: true, id: finalIntermediateId });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Intermediate CA setup error:', message);
    return Response.json({ error: message }, { status: 400 });
  }
}

async function handleCertCreate(context: ApiContext): Promise<Response> {
  const { database, paths, request } = context;
  try {
    const body = (await request.json()) as {
      issuerId?: string;
      domain?: string;
      sanDomains?: string[];
      validityDays?: number;
      keySize?: number;
      hashAlgo?: string;
    };
    const issuerId = (body.issuerId ?? '').trim();
    const domain = (body.domain ?? '').trim().toLowerCase();
    if (!issuerId || !domain) {
      return Response.json({ error: 'issuerId und domain erforderlich' }, { status: 400 });
    }
    const sanDomains = Array.isArray(body.sanDomains)
      ? body.sanDomains.map((value) => String(value).trim().toLowerCase()).filter(Boolean)
      : [];
    const certificateId = createLeafCertificate(database, paths, issuerId, domain, {
      sanDomains,
      validityDays: body.validityDays,
      keySize: body.keySize,
      hashAlgorithm: body.hashAlgo,
    });
    return Response.json({ ok: true, id: certificateId });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Cert create error:', message);
    return Response.json({ error: message }, { status: 400 });
  }
}

async function handleCertDownload(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const idParameter = url.searchParams.get('id');
  if (!idParameter) return new Response('id fehlt', { status: 400 });
  const certificateId = parseInt(idParameter, 10);
  if (isNaN(certificateId)) return new Response('Ungültige id', { status: 400 });
  const certificateRow = database
    .prepare('SELECT pem FROM certificates WHERE id = ?')
    .get(certificateId) as { pem: string | null } | undefined;
  if (!certificateRow?.pem) {
    return new Response('Zertifikat nicht gefunden', { status: 404 });
  }
  return new Response(certificateRow.pem, {
    headers: {
      'Content-Type': 'application/x-pem-file',
      'Content-Disposition': `attachment; filename="cert-${certificateId}.pem"`,
    },
  });
}

async function handleCertKey(context: ApiContext): Promise<Response> {
  const { paths, url } = context;
  const idParameter = url.searchParams.get('id');
  if (!idParameter) return new Response('id fehlt', { status: 400 });
  const certificateId = parseInt(idParameter, 10);
  if (isNaN(certificateId)) return new Response('Ungültige id', { status: 400 });
  const keyPath = paths.leafKeyPath(certificateId);
  if (!existsSync(keyPath)) {
    return new Response('Schlüssel nicht gefunden', { status: 404 });
  }
  const keyPem = readFileSync(keyPath, 'utf8');
  return new Response(keyPem, {
    headers: {
      'Content-Type': 'application/x-pem-file',
      'Content-Disposition': `attachment; filename="cert-${certificateId}-key.pem"`,
    },
  });
}

async function handleCertDelete(context: ApiContext): Promise<Response> {
  const { database, paths, url } = context;
  const idParameter = url.searchParams.get('id');
  if (!idParameter) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const certificateId = parseInt(idParameter, 10);
  if (isNaN(certificateId)) return Response.json({ error: 'Ungültige id' }, { status: 400 });
  const row = database.prepare('SELECT id FROM certificates WHERE id = ?').get(certificateId);
  if (!row) return Response.json({ error: 'Zertifikat nicht gefunden' }, { status: 404 });
  database.prepare('DELETE FROM revoked_certificates WHERE cert_id = ?').run(certificateId);
  database.prepare('DELETE FROM certificates WHERE id = ?').run(certificateId);
  const keyPath = paths.leafKeyPath(certificateId);
  if (existsSync(keyPath)) {
    try {
      unlinkSync(keyPath);
    } catch {
      // Key-Datei konnte nicht gelöscht werden, DB-Eintrag ist weg
    }
  }
  return Response.json({ ok: true });
}

async function handleCertRevoke(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const idParam = url.searchParams.get('id');
  if (!idParam) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const certId = parseInt(idParam, 10);
  if (isNaN(certId)) return Response.json({ error: 'Ungültige id' }, { status: 400 });
  const row = database.prepare('SELECT id FROM certificates WHERE id = ?').get(certId);
  if (!row) return Response.json({ error: 'Zertifikat nicht gefunden' }, { status: 404 });
  const revoked = database.prepare('SELECT 1 FROM revoked_certificates WHERE cert_id = ?').get(certId);
  if (revoked) return Response.json({ error: 'Zertifikat ist bereits widerrufen' }, { status: 400 });
  database.prepare('INSERT INTO revoked_certificates (cert_id) VALUES (?)').run(certId);
  return Response.json({ ok: true });
}

async function handleCertRevocationStatus(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const idParam = url.searchParams.get('id');
  if (!idParam) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const certId = parseInt(idParam, 10);
  if (isNaN(certId)) return Response.json({ error: 'Ungültige id' }, { status: 400 });
  const certRow = database.prepare('SELECT id FROM certificates WHERE id = ?').get(certId);
  if (!certRow) return Response.json({ error: 'Zertifikat nicht gefunden' }, { status: 404 });
  const revRow = database
    .prepare('SELECT revoked_at FROM revoked_certificates WHERE cert_id = ?')
    .get(certId) as { revoked_at: string } | undefined;
  return Response.json({
    revoked: !!revRow,
    revokedAt: revRow?.revoked_at ?? null,
  });
}

function firstCertFromChain(chainPem: string): string {
  const begin = '-----BEGIN CERTIFICATE-----';
  const end = '-----END CERTIFICATE-----';
  const start = chainPem.indexOf(begin);
  if (start === -1) return chainPem;
  const endIdx = chainPem.indexOf(end, start);
  if (endIdx === -1) return chainPem;
  return chainPem.slice(start, endIdx + end.length);
}

async function handleCertInfo(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const idParam = url.searchParams.get('id');
  if (!idParam) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const certId = parseInt(idParam, 10);
  if (isNaN(certId)) return Response.json({ error: 'Ungültige id' }, { status: 400 });
  const row = database
    .prepare('SELECT id, domain, not_after, created_at, pem, issuer_id, ca_certificate_id FROM certificates WHERE id = ?')
    .get(certId) as
    | { id: number; domain: string; not_after: string | null; created_at: string | null; pem: string | null; issuer_id: string | null; ca_certificate_id: number | null }
    | undefined;
  if (!row) return Response.json({ error: 'Zertifikat nicht gefunden' }, { status: 404 });
  let pem: string | null = row.pem;
  if (!pem && row.ca_certificate_id != null) {
    const chainRow = database
      .prepare('SELECT pem FROM ca_certificates WHERE id = ?')
      .get(row.ca_certificate_id) as { pem: string } | undefined;
    pem = chainRow?.pem ?? null;
  }
  if (!pem) return Response.json({ error: 'Zertifikat nicht gefunden' }, { status: 404 });
  const leafPem = pem.includes('-----BEGIN CERTIFICATE-----') && (pem.match(/-----BEGIN CERTIFICATE-----/g)?.length ?? 0) > 1
    ? firstCertFromChain(pem)
    : pem;
  const parsed = parseCertInfo(leafPem);
  const info = {
    type: 'cert' as const,
    id: row.id,
    domain: row.domain,
    notAfter: row.not_after,
    createdAt: row.created_at,
    issuerId: row.issuer_id,
    pem,
    ...(parsed ?? {}),
  };
  return Response.json(info);
}

async function handleCaInfo(context: ApiContext): Promise<Response> {
  const { database, paths, url } = context;
  const caId = url.searchParams.get('id');
  if (!caId) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const rootRow = database
    .prepare('SELECT id, name, common_name, not_after, created_at FROM cas WHERE id = ?')
    .get(caId) as
    | { id: string; name: string; common_name: string; not_after: string | null; created_at: string | null }
    | undefined;
  if (rootRow) {
    const certPath = paths.caCertPath(caId);
    if (!existsSync(certPath)) return Response.json({ error: 'CA-Zertifikat nicht gefunden' }, { status: 404 });
    const pem = readFileSync(certPath, 'utf8');
    const parsed = parseCertInfo(pem);
    return Response.json({
      type: 'root' as const,
      id: rootRow.id,
      name: rootRow.name,
      commonName: rootRow.common_name,
      notAfter: rootRow.not_after,
      createdAt: rootRow.created_at,
      pem,
      ...(parsed ?? {}),
    });
  }
  const intRow = database
    .prepare('SELECT id, parent_ca_id, name, common_name, not_after, created_at FROM intermediate_cas WHERE id = ?')
    .get(caId) as
    | { id: string; parent_ca_id: string; name: string; common_name: string; not_after: string | null; created_at: string | null }
    | undefined;
  if (!intRow) return Response.json({ error: 'CA nicht gefunden' }, { status: 404 });
  const certPath = paths.intermediateCertPath(caId);
  if (!existsSync(certPath)) return Response.json({ error: 'CA-Zertifikat nicht gefunden' }, { status: 404 });
  const pem = readFileSync(certPath, 'utf8');
  const parsed = parseCertInfo(pem);
  return Response.json({
    type: 'intermediate' as const,
    id: intRow.id,
    parentCaId: intRow.parent_ca_id,
    name: intRow.name,
    commonName: intRow.common_name,
    notAfter: intRow.not_after,
    createdAt: intRow.created_at,
    pem,
    ...(parsed ?? {}),
  });
}

function deleteLeafCertsByIssuer(database: Database, paths: PathHelpers, issuerId: string): void {
  const rows = database.prepare('SELECT id FROM certificates WHERE issuer_id = ?').all(issuerId) as Array<{ id: number }>;
  for (const row of rows) {
    database.prepare('DELETE FROM revoked_certificates WHERE cert_id = ?').run(row.id);
    database.prepare('DELETE FROM certificates WHERE id = ?').run(row.id);
    const keyPath = paths.leafKeyPath(row.id);
    if (existsSync(keyPath)) {
      try {
        unlinkSync(keyPath);
      } catch {
        // ignore
      }
    }
  }
}

async function handleCaDelete(context: ApiContext): Promise<Response> {
  const { database, paths, url } = context;
  const caId = url.searchParams.get('id');
  if (!caId) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const rootRow = database.prepare('SELECT 1 FROM cas WHERE id = ?').get(caId);
  if (!rootRow) return Response.json({ error: 'Root-CA nicht gefunden' }, { status: 404 });

  const intermediates = database
    .prepare('SELECT id FROM intermediate_cas WHERE parent_ca_id = ?')
    .all(caId) as Array<{ id: string }>;
  for (const int of intermediates) {
    deleteLeafCertsByIssuer(database, paths, int.id);
    const keyPath = paths.intermediateKeyPath(int.id);
    const certPath = paths.intermediateCertPath(int.id);
    if (existsSync(keyPath)) try { unlinkSync(keyPath); } catch { /* ignore */ }
    if (existsSync(certPath)) try { unlinkSync(certPath); } catch { /* ignore */ }
    database.prepare('DELETE FROM intermediate_cas WHERE id = ?').run(int.id);
  }
  deleteLeafCertsByIssuer(database, paths, caId);
  const rootKeyPath = paths.caKeyPath(caId);
  const rootCertPath = paths.caCertPath(caId);
  if (existsSync(rootKeyPath)) try { unlinkSync(rootKeyPath); } catch { /* ignore */ }
  if (existsSync(rootCertPath)) try { unlinkSync(rootCertPath); } catch { /* ignore */ }
  database.prepare('DELETE FROM cas WHERE id = ?').run(caId);
  const activeId = database.prepare(`SELECT value FROM config WHERE key = ?`).get(CONFIG_KEY_ACTIVE_CA_ID) as { value: string } | undefined;
  if (activeId && activeId.value === caId) {
    database.prepare('DELETE FROM config WHERE key = ?').run(CONFIG_KEY_ACTIVE_CA_ID);
  }
  return Response.json({ ok: true });
}

async function handleCaIntermediateDelete(context: ApiContext): Promise<Response> {
  const { database, paths, url } = context;
  const id = url.searchParams.get('id');
  if (!id) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const row = database.prepare('SELECT 1 FROM intermediate_cas WHERE id = ?').get(id);
  if (!row) return Response.json({ error: 'Intermediate-CA nicht gefunden' }, { status: 404 });
  deleteLeafCertsByIssuer(database, paths, id);
  const keyPath = paths.intermediateKeyPath(id);
  const certPath = paths.intermediateCertPath(id);
  if (existsSync(keyPath)) try { unlinkSync(keyPath); } catch { /* ignore */ }
  if (existsSync(certPath)) try { unlinkSync(certPath); } catch { /* ignore */ }
  database.prepare('DELETE FROM intermediate_cas WHERE id = ?').run(id);
  return Response.json({ ok: true });
}

async function handleChallengesDelete(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const idParam = url.searchParams.get('id');
  if (!idParam) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const id = parseInt(idParam, 10);
  if (isNaN(id)) return Response.json({ error: 'Ungültige id' }, { status: 400 });
  const row = database.prepare('SELECT 1 FROM challenges WHERE id = ?').get(id);
  if (!row) return Response.json({ error: 'Challenge nicht gefunden' }, { status: 404 });
  database.prepare('DELETE FROM challenges WHERE id = ?').run(id);
  return Response.json({ ok: true });
}

async function handleAcmeAuthzDelete(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const authzId = url.searchParams.get('id');
  if (!authzId) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const row = database.prepare('SELECT 1 FROM ca_authorizations WHERE authz_id = ?').get(authzId);
  if (!row) return Response.json({ error: 'ACME-Authorisierung nicht gefunden' }, { status: 404 });
  database.prepare('DELETE FROM ca_challenges WHERE authz_id = ?').run(authzId);
  database.prepare('DELETE FROM ca_authorizations WHERE authz_id = ?').run(authzId);
  return Response.json({ ok: true });
}

async function handleAcmeChallengeAccept(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const authzId = url.searchParams.get('id');
  if (!authzId) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const row = database.prepare('SELECT 1 FROM ca_authorizations WHERE authz_id = ?').get(authzId);
  if (!row) return Response.json({ error: 'ACME-Authorisierung nicht gefunden' }, { status: 404 });
  database.prepare('UPDATE ca_challenges SET status = ? WHERE authz_id = ?').run('valid', authzId);
  database.prepare('UPDATE ca_authorizations SET status = ? WHERE authz_id = ?').run('valid', authzId);
  return Response.json({ ok: true });
}

const API_ROUTES: Array<{
  method: string;
  path: string;
  handler: (context: ApiContext) => Promise<Response>;
}> = [
  { method: 'GET', path: '/api/events', handler: handleEvents },
  { method: 'GET', path: '/api/ca-cert', handler: handleCaCert },
  { method: 'POST', path: '/api/ca/setup', handler: handleCaSetup },
  { method: 'POST', path: '/api/ca/activate', handler: handleCaActivate },
  { method: 'POST', path: '/api/ca/intermediate', handler: handleCaIntermediate },
  { method: 'POST', path: '/api/cert/create', handler: handleCertCreate },
  { method: 'GET', path: '/api/cert/download', handler: handleCertDownload },
  { method: 'GET', path: '/api/cert/info', handler: handleCertInfo },
  { method: 'GET', path: '/api/cert/key', handler: handleCertKey },
  { method: 'POST', path: '/api/cert/revoke', handler: handleCertRevoke },
  { method: 'GET', path: '/api/cert/revocation-status', handler: handleCertRevocationStatus },
  { method: 'DELETE', path: '/api/cert', handler: handleCertDelete },
  { method: 'GET', path: '/api/ca/info', handler: handleCaInfo },
  { method: 'DELETE', path: '/api/ca', handler: handleCaDelete },
  { method: 'DELETE', path: '/api/ca/intermediate', handler: handleCaIntermediateDelete },
  { method: 'DELETE', path: '/api/challenges', handler: handleChallengesDelete },
  { method: 'DELETE', path: '/api/acme-authz', handler: handleAcmeAuthzDelete },
  { method: 'POST', path: '/api/acme-challenge/accept', handler: handleAcmeChallengeAccept },
];

export async function handleApi(
  database: Database,
  paths: PathHelpers,
  request: Request
): Promise<Response> {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const context: ApiContext = { database, paths, request, url };

  for (const route of API_ROUTES) {
    if (route.method === request.method && route.path === pathname) {
      return route.handler(context);
    }
  }

  return new Response('Not found', { status: 404 });
}
