import * as crypto from 'node:crypto';
import type { Database } from 'bun:sqlite';
import { existsSync, readFileSync } from 'node:fs';
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
  { method: 'GET', path: '/api/cert/key', handler: handleCertKey },
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
