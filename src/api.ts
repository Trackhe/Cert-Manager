import * as crypto from 'node:crypto';
import type { Database } from 'bun:sqlite';
import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import {
  createRootCa,
  createIntermediateCa,
  getActiveAcmeIntermediateId,
  getActiveCaId,
} from './ca.js';
import { createLeafCertificate } from './leaf-certificate.js';
import {
  CONFIG_KEY_ACTIVE_ACME_INTERMEDIATE_ID,
  CONFIG_KEY_ACTIVE_CA_ID,
  CONFIG_KEY_DEFAULT_COMMON_NAME_INTERMEDIATE,
  CONFIG_KEY_DEFAULT_COMMON_NAME_ROOT,
  getConfigValue,
} from './database.js';
import { addLogStreamClient, getLogLines, logger } from './logger.js';
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
  /** z. B. RSA, EC */
  keyType: string | null;
  /** RSA: Bit-Länge (z. B. 2048); EC: Kurve (z. B. P-256) */
  keyInfo: string | null;
  /** z. B. RSA-SHA256, ECDSA-SHA256 */
  signatureAlgorithm: string | null;
};

function parseCertInfo(pem: string): CertInfoParsed | null {
  try {
    const x = new X509Certificate(pem);
    const san =
      typeof (x as unknown as { subjectAltName?: string }).subjectAltName === 'string'
        ? (x as unknown as { subjectAltName: string }).subjectAltName
        : null;
    const keyType = x.publicKey?.asymmetricKeyType ?? null;
    let keyInfo: string | null = null;
    if (keyType === 'rsa' && typeof (x.publicKey as crypto.KeyObject & { asymmetricKeySize?: number }).asymmetricKeySize === 'number') {
      keyInfo = String((x.publicKey as crypto.KeyObject & { asymmetricKeySize: number }).asymmetricKeySize) + ' Bit';
    } else if (keyType === 'ec') {
      try {
        const jwk = (x.publicKey as crypto.KeyObject).export({ format: 'jwk' }) as { crv?: string } | undefined;
        keyInfo = jwk?.crv ?? 'EC';
      } catch {
        keyInfo = 'EC';
      }
    } else if (keyType) {
      keyInfo = keyType.toUpperCase();
    }
    const sigAlg = (x as unknown as { signatureAlgorithm?: string }).signatureAlgorithm ?? null;
    return {
      subject: x.subject,
      issuer: x.issuer,
      serialNumber: x.serialNumber,
      notBefore: x.validFrom,
      notAfter: x.validTo,
      fingerprint256: x.fingerprint256,
      subjectAltName: san,
      keyType: keyType ? String(keyType).toUpperCase() : null,
      keyInfo,
      signatureAlgorithm: sigAlg ?? null,
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

/** Liefert die numerische Query-Param-ID oder null bei fehlendem/ungültigem Wert. */
function parseIdParam(url: URL, param = 'id'): number | null {
  const raw = url.searchParams.get(param);
  if (raw == null || raw === '') return null;
  const n = parseInt(raw, 10);
  return Number.isNaN(n) ? null : n;
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

async function handleLog(): Promise<Response> {
  return Response.json({ lines: getLogLines() });
}

async function handleStatsHistory(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const daysParam = url.searchParams.get('days');
  const days = Math.min(90, Math.max(7, parseInt(daysParam ?? '30', 10) || 30));

  const since = new Date();
  since.setDate(since.getDate() - days);
  const sinceStr = since.toISOString().slice(0, 10);

  const certsCreated = database
    .prepare(
      `SELECT date(created_at) as d, COUNT(*) as c FROM certificates WHERE created_at >= ? GROUP BY d ORDER BY d`
    )
    .all(sinceStr) as Array<{ d: string; c: number }>;

  const certsRevoked = database
    .prepare(
      `SELECT date(revoked_at) as d, COUNT(*) as c FROM revoked_certificates WHERE revoked_at >= ? GROUP BY d ORDER BY d`
    )
    .all(sinceStr) as Array<{ d: string; c: number }>;

  const acmeOrders = database
    .prepare(
      `SELECT date(created_at) as d, COUNT(*) as c FROM ca_orders WHERE created_at >= ? GROUP BY d ORDER BY d`
    )
    .all(sinceStr) as Array<{ d: string; c: number }>;

  const certsRenewed = database
    .prepare(
      `SELECT date(renewed_at) as d, COUNT(*) as c FROM cert_renewals WHERE renewed_at >= ? GROUP BY d ORDER BY d`
    )
    .all(sinceStr) as Array<{ d: string; c: number }>;

  const requests = database
    .prepare(`SELECT date, count FROM request_stats WHERE date >= ? ORDER BY date`)
    .all(sinceStr) as Array<{ date: string; count: number }>;

  const certsCreatedByDay = certsCreated.map((r) => ({ date: r.d, count: r.c }));
  const certsRevokedByDay = certsRevoked.map((r) => ({ date: r.d, count: r.c }));
  const certsRenewedByDay = certsRenewed.map((r) => ({ date: r.d, count: r.c }));
  const acmeOrdersByDay = acmeOrders.map((r) => ({ date: r.d, count: r.c }));
  const requestsByDay = requests.map((r) => ({ date: r.date, count: r.count }));

  return Response.json({
    days,
    since: sinceStr,
    certsCreatedByDay,
    certsRevokedByDay,
    certsRenewedByDay,
    acmeOrdersByDay,
    requestsByDay,
  });
}

async function handleLogStream(context: ApiContext): Promise<Response> {
  const { request } = context;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const encoder = new TextEncoder();
      for (const line of getLogLines()) {
        controller.enqueue(encoder.encode('data: ' + JSON.stringify(line) + '\n\n'));
      }
      const unsubscribe = addLogStreamClient((line) => {
        try {
          controller.enqueue(encoder.encode('data: ' + JSON.stringify(line) + '\n\n'));
        } catch {
          // client closed
        }
      });
      request.signal?.addEventListener('abort', () => {
        unsubscribe();
        controller.close();
      });
    },
  });
  return new Response(stream, {
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
    const defaultCnRoot = getConfigValue(database, CONFIG_KEY_DEFAULT_COMMON_NAME_ROOT) ?? 'Meine CA';
    const name = (body.name ?? body.commonName ?? defaultCnRoot).trim();
    const commonName = (body.commonName ?? name).trim();
    const slug = slugFromName(name);
    const existingCa = database.prepare('SELECT 1 FROM cas WHERE id = ?').get(slug);
    const finalCaId = existingCa ? slug + '-' + Date.now().toString(36) : slug;
    createRootCa(database, paths, finalCaId, {
      name: name || commonName,
      commonName: commonName || defaultCnRoot,
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
    logger.info('Root-CA erstellt', { caId: finalCaId, name: name || commonName });
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
  logger.info('Aktive CA gesetzt', { caId });
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
    const defaultCnInt =
      getConfigValue(database, CONFIG_KEY_DEFAULT_COMMON_NAME_INTERMEDIATE) ?? 'Intermediate CA';
    const name = (body.name ?? body.commonName ?? defaultCnInt).trim();
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
      commonName: commonName || defaultCnInt,
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
    logger.info('Intermediate-CA erstellt', { intermediateId: finalIntermediateId, parentCaId });
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
    logger.info('Zertifikat erstellt', { certId: certificateId, domain, issuerId, sanDomains: sanDomains.length ? sanDomains : undefined });
    return Response.json({ ok: true, id: certificateId });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('Cert create error:', message);
    return Response.json({ error: message }, { status: 400 });
  }
}

async function handleCertDownload(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const certificateId = parseIdParam(url);
  if (certificateId === null) return new Response('id fehlt oder ungültig', { status: 400 });
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
  const certificateId = parseIdParam(url);
  if (certificateId === null) return new Response('id fehlt oder ungültig', { status: 400 });
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
  const certificateId = parseIdParam(url);
  if (certificateId === null) return Response.json({ error: 'id fehlt oder ungültig' }, { status: 400 });
  const row = database.prepare('SELECT id, domain FROM certificates WHERE id = ?').get(certificateId) as { id: number; domain: string } | undefined;
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
  logger.info('Zertifikat gelöscht', { certId: certificateId, domain: row.domain });
  return Response.json({ ok: true });
}

async function handleCertRevoke(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const certId = parseIdParam(url);
  if (certId === null) return Response.json({ error: 'id fehlt oder ungültig' }, { status: 400 });
  const row = database.prepare('SELECT id, domain FROM certificates WHERE id = ?').get(certId) as { id: number; domain: string } | undefined;
  if (!row) return Response.json({ error: 'Zertifikat nicht gefunden' }, { status: 404 });
  const revoked = database.prepare('SELECT 1 FROM revoked_certificates WHERE cert_id = ?').get(certId);
  if (revoked) return Response.json({ error: 'Zertifikat ist bereits widerrufen' }, { status: 400 });
  database.prepare('INSERT INTO revoked_certificates (cert_id) VALUES (?)').run(certId);
  logger.info('Zertifikat widerrufen', { certId, domain: row.domain });
  return Response.json({ ok: true });
}

async function handleCertRenew(context: ApiContext): Promise<Response> {
  const { database, paths, request } = context;
  try {
    const body = (await request.json()) as { id?: number };
    const certId = typeof body.id === 'number' ? body.id : parseInt(String(body.id ?? ''), 10);
    if (Number.isNaN(certId)) return Response.json({ error: 'id fehlt oder ungültig' }, { status: 400 });
    const certRow = database
      .prepare('SELECT id, domain, issuer_id FROM certificates WHERE id = ?')
      .get(certId) as { id: number; domain: string; issuer_id: string | null } | undefined;
    if (!certRow) return Response.json({ error: 'Zertifikat nicht gefunden' }, { status: 404 });
    const revoked = database.prepare('SELECT 1 FROM revoked_certificates WHERE cert_id = ?').get(certId);
    if (revoked) return Response.json({ error: 'Zertifikat ist bereits widerrufen' }, { status: 400 });
    const issuerId = certRow.issuer_id ?? getActiveCaId(database);
    if (!issuerId) return Response.json({ error: 'Keine CA zum Ausstellen gefunden' }, { status: 400 });
    database.prepare('INSERT INTO revoked_certificates (cert_id) VALUES (?)').run(certId);
    database.prepare('INSERT INTO cert_renewals (renewed_at) VALUES (datetime("now"))').run();
    const newId = createLeafCertificate(database, paths, issuerId, certRow.domain, {});
    logger.info('Zertifikat erneuert', { oldCertId: certId, newCertId: newId, domain: certRow.domain });
    return Response.json({ ok: true, id: newId });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return Response.json({ error: message }, { status: 400 });
  }
}

async function handleCertRevocationStatus(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const certId = parseIdParam(url);
  if (certId === null) return Response.json({ error: 'id fehlt oder ungültig' }, { status: 400 });
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
  return endIdx === -1 ? chainPem : chainPem.slice(start, endIdx + end.length);
}

async function handleCertInfo(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const certId = parseIdParam(url);
  if (certId === null) return Response.json({ error: 'id fehlt oder ungültig' }, { status: 400 });
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
  const leafPem = (pem.match(/-----BEGIN CERTIFICATE-----/g)?.length ?? 0) > 1 ? firstCertFromChain(pem) : pem;
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
  database.prepare('DELETE FROM acme_ca_domain_assignments WHERE ca_id = ?').run(caId);
  database.prepare('DELETE FROM cas WHERE id = ?').run(caId);
  const activeId = database.prepare(`SELECT value FROM config WHERE key = ?`).get(CONFIG_KEY_ACTIVE_CA_ID) as { value: string } | undefined;
  if (activeId && activeId.value === caId) {
    database.prepare('DELETE FROM config WHERE key = ?').run(CONFIG_KEY_ACTIVE_CA_ID);
  }
  logger.info('Root-CA gelöscht', { caId });
  return Response.json({ ok: true });
}

async function handleCaIntermediateDelete(context: ApiContext): Promise<Response> {
  const { database, paths, url } = context;
  const id = url.searchParams.get('id');
  if (!id) return Response.json({ error: 'id fehlt' }, { status: 400 });
  const row = database.prepare('SELECT 1 FROM intermediate_cas WHERE id = ?').get(id);
  if (!row) return Response.json({ error: 'Intermediate-CA nicht gefunden' }, { status: 404 });
  deleteLeafCertsByIssuer(database, paths, id);
  database.prepare('DELETE FROM acme_ca_domain_assignments WHERE ca_id = ?').run(id);
  const keyPath = paths.intermediateKeyPath(id);
  const certPath = paths.intermediateCertPath(id);
  if (existsSync(keyPath)) try { unlinkSync(keyPath); } catch { /* ignore */ }
  if (existsSync(certPath)) try { unlinkSync(certPath); } catch { /* ignore */ }
  database.prepare('DELETE FROM intermediate_cas WHERE id = ?').run(id);
  logger.info('Intermediate-CA gelöscht', { intermediateId: id });
  return Response.json({ ok: true });
}

async function handleChallengesDelete(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const id = parseIdParam(url);
  if (id === null) return Response.json({ error: 'id fehlt oder ungültig' }, { status: 400 });
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
  const acceptedAt = Math.floor(Date.now() / 1000);
  const authzRow = database.prepare('SELECT identifier FROM ca_authorizations WHERE authz_id = ?').get(authzId) as { identifier: string } | undefined;
  database.prepare('UPDATE ca_challenges SET status = ?, accepted_at = ? WHERE authz_id = ?').run('valid', acceptedAt, authzId);
  database.prepare('UPDATE ca_authorizations SET status = ? WHERE authz_id = ?').run('valid', authzId);
  logger.info('ACME-Challenge manuell akzeptiert', { authzId, identifier: authzRow?.identifier });
  return Response.json({ ok: true });
}

async function handleAcmeWhitelistPost(context: ApiContext): Promise<Response> {
  const { database, request } = context;
  try {
    const body = (await request.json()) as { domain?: string };
    const domain = typeof body.domain === 'string' ? body.domain.trim().toLowerCase() : '';
    if (!domain) return Response.json({ error: 'domain fehlt oder leer' }, { status: 400 });
    const result = database.prepare('INSERT OR IGNORE INTO acme_whitelist_domains (domain) VALUES (?)').run(domain);
    if (result.changes === 0) return Response.json({ error: 'Domain ist bereits in der Whitelist' }, { status: 400 });
    logger.info('ACME-Whitelist: Domain hinzugefügt', { domain });
  } catch {
    return Response.json({ error: 'Ungültige Anfrage' }, { status: 400 });
  }
  return Response.json({ ok: true });
}

async function handleAcmeWhitelistDelete(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const id = parseIdParam(url);
  if (id === null) return Response.json({ error: 'id fehlt oder ungültig' }, { status: 400 });
  const row = database.prepare('SELECT domain FROM acme_whitelist_domains WHERE id = ?').get(id) as { domain: string } | undefined;
  const result = database.prepare('DELETE FROM acme_whitelist_domains WHERE id = ?').run(id);
  if (result.changes === 0) return Response.json({ error: 'Eintrag nicht gefunden' }, { status: 404 });
  logger.info('ACME-Whitelist: Domain entfernt', { id, domain: row?.domain });
  return Response.json({ ok: true });
}

async function handleAcmeCaAssignmentsGet(context: ApiContext): Promise<Response> {
  const { database } = context;
  const rows = database
    .prepare('SELECT domain_pattern AS domainPattern, ca_id AS caId FROM acme_ca_domain_assignments ORDER BY domain_pattern')
    .all() as Array<{ domainPattern: string; caId: string }>;
  return Response.json({ assignments: rows });
}

async function handleAcmeCaAssignmentsPost(context: ApiContext): Promise<Response> {
  const { database, request } = context;
  try {
    const body = (await request.json()) as { domain_pattern?: string; domainPattern?: string; ca_id?: string; caId?: string };
    const pattern = (body.domain_pattern ?? body.domainPattern ?? '').trim().toLowerCase();
    const caId = body.ca_id ?? body.caId ?? '';
    if (!pattern) return Response.json({ error: 'domain_pattern fehlt oder leer' }, { status: 400 });
    if (!caId) return Response.json({ error: 'ca_id fehlt' }, { status: 400 });
    const isRoot = database.prepare('SELECT 1 FROM cas WHERE id = ?').get(caId);
    const isIntermediate = database.prepare('SELECT 1 FROM intermediate_cas WHERE id = ?').get(caId);
    if (!isRoot && !isIntermediate) return Response.json({ error: 'CA nicht gefunden (Root oder Intermediate)' }, { status: 400 });
    database.prepare('INSERT OR REPLACE INTO acme_ca_domain_assignments (domain_pattern, ca_id) VALUES (?, ?)').run(pattern, caId);
    logger.info('ACME CA-Zuordnung gesetzt', { domainPattern: pattern, caId });
  } catch {
    return Response.json({ error: 'Ungültige Anfrage' }, { status: 400 });
  }
  return Response.json({ ok: true });
}

async function handleAcmeCaAssignmentsDelete(context: ApiContext): Promise<Response> {
  const { database, url } = context;
  const pattern = url.searchParams.get('pattern') ?? '';
  const normalized = pattern.trim().toLowerCase();
  if (!normalized) return Response.json({ error: 'pattern fehlt' }, { status: 400 });
  const result = database.prepare('DELETE FROM acme_ca_domain_assignments WHERE domain_pattern = ?').run(normalized);
  if (result.changes === 0) return Response.json({ error: 'Eintrag nicht gefunden' }, { status: 404 });
  logger.info('ACME CA-Zuordnung entfernt', { domainPattern: normalized });
  return Response.json({ ok: true });
}

async function handleAcmeDefaultIntermediateGet(context: ApiContext): Promise<Response> {
  const { database } = context;
  const id = getActiveAcmeIntermediateId(database);
  return Response.json({ intermediateId: id });
}

async function handleAcmeDefaultIntermediatePost(context: ApiContext): Promise<Response> {
  const { database, request } = context;
  try {
    const body = (await request.json()) as { id?: string | null };
    const id = body.id == null || body.id === '' ? null : String(body.id).trim();
    if (id !== null) {
      const row = database.prepare('SELECT 1 FROM intermediate_cas WHERE id = ?').get(id);
      if (!row) return Response.json({ error: 'Intermediate-CA nicht gefunden' }, { status: 404 });
    }
    if (id === null || id === '') {
      database.prepare('DELETE FROM config WHERE key = ?').run(CONFIG_KEY_ACTIVE_ACME_INTERMEDIATE_ID);
    } else {
      database
        .prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)')
        .run(CONFIG_KEY_ACTIVE_ACME_INTERMEDIATE_ID, id);
    }
    logger.info('ACME Standard-Intermediate gesetzt', { intermediateId: id || '(keine)' });
  } catch {
    return Response.json({ error: 'Ungültige Anfrage' }, { status: 400 });
  }
  return Response.json({ ok: true });
}

const API_ROUTES: Array<{
  method: string;
  path: string;
  handler: (context: ApiContext) => Promise<Response>;
}> = [
  { method: 'GET', path: '/api/events', handler: handleEvents },
  { method: 'GET', path: '/api/log', handler: handleLog },
  { method: 'GET', path: '/api/log/stream', handler: handleLogStream },
  { method: 'GET', path: '/api/stats/history', handler: handleStatsHistory },
  { method: 'GET', path: '/api/ca-cert', handler: handleCaCert },
  { method: 'POST', path: '/api/ca/setup', handler: handleCaSetup },
  { method: 'POST', path: '/api/ca/activate', handler: handleCaActivate },
  { method: 'POST', path: '/api/ca/intermediate', handler: handleCaIntermediate },
  { method: 'POST', path: '/api/cert/create', handler: handleCertCreate },
  { method: 'GET', path: '/api/cert/download', handler: handleCertDownload },
  { method: 'GET', path: '/api/cert/info', handler: handleCertInfo },
  { method: 'GET', path: '/api/cert/key', handler: handleCertKey },
  { method: 'POST', path: '/api/cert/revoke', handler: handleCertRevoke },
  { method: 'POST', path: '/api/cert/renew', handler: handleCertRenew },
  { method: 'GET', path: '/api/cert/revocation-status', handler: handleCertRevocationStatus },
  { method: 'DELETE', path: '/api/cert', handler: handleCertDelete },
  { method: 'GET', path: '/api/ca/info', handler: handleCaInfo },
  { method: 'DELETE', path: '/api/ca', handler: handleCaDelete },
  { method: 'DELETE', path: '/api/ca/intermediate', handler: handleCaIntermediateDelete },
  { method: 'DELETE', path: '/api/challenges', handler: handleChallengesDelete },
  { method: 'DELETE', path: '/api/acme-authz', handler: handleAcmeAuthzDelete },
  { method: 'POST', path: '/api/acme-challenge/accept', handler: handleAcmeChallengeAccept },
  { method: 'POST', path: '/api/acme-whitelist', handler: handleAcmeWhitelistPost },
  { method: 'DELETE', path: '/api/acme-whitelist', handler: handleAcmeWhitelistDelete },
  { method: 'GET', path: '/api/acme-ca-assignments', handler: handleAcmeCaAssignmentsGet },
  { method: 'POST', path: '/api/acme-ca-assignments', handler: handleAcmeCaAssignmentsPost },
  { method: 'DELETE', path: '/api/acme-ca-assignments', handler: handleAcmeCaAssignmentsDelete },
  { method: 'GET', path: '/api/acme-default-intermediate', handler: handleAcmeDefaultIntermediateGet },
  { method: 'POST', path: '/api/acme-default-intermediate', handler: handleAcmeDefaultIntermediatePost },
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
