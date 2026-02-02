import * as crypto from 'node:crypto';
import type { Database } from 'bun:sqlite';
// @ts-expect-error no types
import * as forge from 'node-forge';
import {
  clearValidating,
  isValidating,
  setValidating,
  updateValidationAttempt,
} from './acme-validation-state.js';
import { getActiveCaId, getCa, getSignerCa } from './ca.js';
import { logger } from './logger.js';
import type { PathHelpers } from './paths.js';

function base64UrlEncode(buffer: string | Buffer): string {
  const data = typeof buffer === 'string' ? Buffer.from(buffer, 'utf8') : Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  return data.toString('base64url');
}

function base64UrlDecode(value: string): string {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function generateNonce(): string {
  return crypto.randomBytes(16).toString('base64url');
}

function jwkThumbprint(jwk: { e: string; kty: string; n: string }): string {
  const keyNames = ['e', 'kty', 'n'].sort();
  const canonical: Record<string, string> = {};
  for (const keyName of keyNames) {
    canonical[keyName] = (jwk as Record<string, string>)[keyName] ?? '';
  }
  return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('base64url');
}

async function parseJws(body: string): Promise<{
  protected: Record<string, unknown>;
  payload: string;
  raw: string;
}> {
  const parsed = JSON.parse(body) as { protected: string; payload: string; signature: string };
  const raw = parsed.protected + '.' + parsed.payload;
  const protectedHeader = JSON.parse(base64UrlDecode(parsed.protected)) as Record<string, unknown>;
  return { protected: protectedHeader, payload: parsed.payload, raw };
}

function verifyJws(body: string, accountKeyPem: string): { payload: unknown } | null {
  try {
    const parsed = JSON.parse(body) as { protected: string; payload: string; signature: string };
    const raw = parsed.protected + '.' + parsed.payload;
    const signatureBuffer = Buffer.from(parsed.signature, 'base64url');
    const publicKey = crypto.createPublicKey(accountKeyPem);
    const isValid = crypto.verify(
      'RSA-SHA256',
      Buffer.from(raw, 'utf8'),
      { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      signatureBuffer
    );
    if (!isValid) return null;
    const payloadBase64 = parsed.payload === '' ? 'e30' : parsed.payload;
    return { payload: JSON.parse(base64UrlDecode(payloadBase64)) as unknown };
  } catch {
    return null;
  }
}

function jwkToPem(jwk: { e: string; kty: string; n: string }): string {
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  return publicKey.export({ type: 'spki', format: 'pem' }) as string;
}

const VALIDATION_MAX_ATTEMPTS = 5;
const VALIDATION_INTERVAL_MS = 5000;
const POLLING_INTERVAL_MS = 15000;

/**
 * Führt die HTTP-01-Validierung für eine Challenge aus (Domain aufrufen, key_authorization prüfen).
 * Wird sowohl vom ACME-POST-Handler als auch vom Hintergrund-Polling aufgerufen.
 */
export async function runChallengeValidation(
  database: Database,
  challengeId: string
): Promise<boolean> {
  const challengeRow = database
    .prepare('SELECT authz_id, token, key_authorization, status FROM ca_challenges WHERE challenge_id = ?')
    .get(challengeId) as { authz_id: string; token: string; key_authorization: string; status: string } | undefined;
  if (!challengeRow) return false;
  if (challengeRow.status === 'valid') return true;

  const authorizationRow = database
    .prepare('SELECT identifier FROM ca_authorizations WHERE authz_id = ?')
    .get(challengeRow.authz_id) as { identifier: string };
  const domain = authorizationRow.identifier;
  const challengePath = `/.well-known/acme-challenge/${challengeRow.token}`;

  setValidating(challengeId, domain);

  for (let attempt = 1; attempt <= VALIDATION_MAX_ATTEMPTS; attempt++) {
    updateValidationAttempt(challengeId, attempt, false, Date.now() + VALIDATION_INTERVAL_MS);
    let responseText: string | null = null;
    try {
      const challengeUrl = `http://${domain}${challengePath}`;
      logger.debug('acme challenge fetch', { domain, challengeUrl, attempt, maxAttempts: VALIDATION_MAX_ATTEMPTS });
      const challengeResponse = await fetch(challengeUrl);
      if (challengeResponse.ok) {
        responseText = (await challengeResponse.text()).trim();
      }
    } catch (err) {
      logger.debug('acme challenge attempt failed', { domain, attempt, error: String(err) });
      updateValidationAttempt(challengeId, attempt, false);
      if (attempt < VALIDATION_MAX_ATTEMPTS) await new Promise((r) => setTimeout(r, VALIDATION_INTERVAL_MS));
      continue;
    }
    if (responseText == null || responseText !== challengeRow.key_authorization) {
      logger.debug('acme challenge response mismatch', { domain, attempt });
      updateValidationAttempt(challengeId, attempt, false);
      if (attempt < VALIDATION_MAX_ATTEMPTS) await new Promise((r) => setTimeout(r, VALIDATION_INTERVAL_MS));
      continue;
    }
    logger.debug('acme challenge valid', { domain, attempt });
    updateValidationAttempt(challengeId, attempt, true);
    database.prepare('UPDATE ca_challenges SET status = ? WHERE challenge_id = ?').run('valid', challengeId);
    database.prepare('UPDATE ca_authorizations SET status = ? WHERE authz_id = ?').run('valid', challengeRow.authz_id);
    return true;
  }

  clearValidating(challengeId);
  logger.debug('acme challenge failed after all attempts', { domain, maxAttempts: VALIDATION_MAX_ATTEMPTS });
  return false;
}

/**
 * Startet das Hintergrund-Polling: Alle ~15 s werden pending Challenges geprüft
 * (Domain aufrufen, ob key_authorization ausgeliefert wird). Dashboard zeigt dann Timer/Zähler.
 */
export function startValidationPolling(database: Database): void {
  setInterval(() => {
    const pending = database
      .prepare(
        `SELECT c.challenge_id AS challengeId FROM ca_challenges c
         JOIN ca_authorizations a ON a.authz_id = c.authz_id
         WHERE c.status = 'pending'`
      )
      .all() as Array<{ challengeId: string }>;
    for (const row of pending) {
      if (!isValidating(row.challengeId)) {
        runChallengeValidation(database, row.challengeId).catch((err) =>
          logger.debug('validation polling error', { challengeId: row.challengeId, error: String(err) })
        );
      }
    }
  }, POLLING_INTERVAL_MS);
  logger.debug('acme validation polling started', { intervalMs: POLLING_INTERVAL_MS });
}

export async function handleAcme(
  database: Database,
  paths: PathHelpers,
  port: number,
  request: Request
): Promise<Response> {
  const url = new URL(request.url);
  const host = request.headers.get('host') ?? `localhost:${port}`;
  const baseUrl = host.startsWith('localhost') ? `http://${host}` : `https://${host}`;
  let pathname = url.pathname;
  if (pathname.endsWith('/') && pathname.length > 1) pathname = pathname.slice(0, -1);

  logger.debug('acme', { pathname, method: request.method, baseUrl });

  if (pathname === '/acme/directory' && request.method === 'GET') {
    logger.debug('acme directory', { pathname });
    return Response.json({
      newNonce: baseUrl + '/acme/new-nonce',
      newAccount: baseUrl + '/acme/new-account',
      newOrder: baseUrl + '/acme/new-order',
    });
  }

  if (pathname === '/acme/new-nonce' && (request.method === 'HEAD' || request.method === 'POST')) {
    logger.debug('acme new-nonce', { method: request.method });
    return new Response(null, {
      status: 204,
      headers: { 'Replay-Nonce': generateNonce(), 'Cache-Control': 'no-store' },
    });
  }

  if (request.method === 'POST' && pathname.startsWith('/acme/')) {
    const bodyText = await request.text();
    logger.debug('acme POST body length', { pathname, bodyLength: bodyText.length });
    const parsed = await parseJws(bodyText).catch((err) => {
      logger.debug('acme JWS parse failed', { pathname, error: String(err) });
      return null;
    });
    if (!parsed) {
      return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 400 });
    }

    const protectedHeader = parsed.protected as {
      url?: string;
      kid?: string;
      jwk?: { e: string; kty: string; n: string };
    };
    const requestUrl = protectedHeader.url as string;
    let accountId: string | null = null;
    let accountKeyPem: string | null = null;

    if (protectedHeader.kid) {
      const kidAccountId = (protectedHeader.kid as string).split('/').pop() ?? '';
      const accountRow = database
        .prepare('SELECT account_id, jwk FROM ca_accounts WHERE account_id = ?')
        .get(kidAccountId) as { account_id: string; jwk: string } | undefined;
      if (!accountRow) {
        return Response.json({ type: 'urn:ietf:params:acme:error:accountDoesNotExist' }, { status: 400 });
      }
      accountId = accountRow.account_id;
      accountKeyPem = jwkToPem(JSON.parse(accountRow.jwk));
    } else if (protectedHeader.jwk) {
      accountKeyPem = jwkToPem(protectedHeader.jwk);
    }

    const verified = accountKeyPem ? verifyJws(bodyText, accountKeyPem) : null;
    if (!verified) {
      return Response.json({ type: 'urn:ietf:params:acme:error:unauthorized' }, { status: 401 });
    }
    const payload = verified.payload as Record<string, unknown>;
    logger.debug('acme POST JWS verified', { requestUrl });

    if (requestUrl === baseUrl + '/acme/new-account') {
      logger.debug('acme new-account');
      const newAccountId = 'acct-' + crypto.randomBytes(8).toString('hex');
      const jwk = protectedHeader.jwk!;
      database.prepare('INSERT OR IGNORE INTO ca_accounts (account_id, jwk) VALUES (?, ?)').run(newAccountId, JSON.stringify(jwk));
      const accountUrl = baseUrl + '/acme/account/' + newAccountId;
      return new Response(
        JSON.stringify({ status: 'valid', orders: baseUrl + '/acme/orders/' + newAccountId }),
        {
          status: 201,
          headers: {
            'Content-Type': 'application/json',
            'Replay-Nonce': generateNonce(),
            Location: accountUrl,
          },
        }
      );
    }

    if (requestUrl === baseUrl + '/acme/new-order') {
      const identifiers = payload.identifiers as Array<{ type: string; value: string }>;
      logger.debug('acme new-order', { identifiers: identifiers?.map((i) => i.value) });
      if (!identifiers?.length) {
        return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 400 });
      }
      const orderId = 'order-' + crypto.randomBytes(8).toString('hex');
      const accountIdFromKid = (protectedHeader.kid as string).split('/').pop() ?? accountId ?? '';
      database.prepare(
        'INSERT INTO ca_orders (order_id, account_id, identifiers, status, finalize_url) VALUES (?, ?, ?, ?, ?)'
      ).run(orderId, accountIdFromKid, JSON.stringify(identifiers), 'pending', baseUrl + '/acme/finalize/' + orderId);

      const accountJwkRow = database.prepare('SELECT jwk FROM ca_accounts WHERE account_id = ?').get(accountIdFromKid) as { jwk: string } | undefined;
      const accountJwk = accountJwkRow ? (JSON.parse(accountJwkRow.jwk) as { e: string; kty: string; n: string }) : null;
      const thumbprint = accountJwk ? jwkThumbprint(accountJwk) : '';
      const authorizationIds: string[] = [];

      for (const identifier of identifiers) {
        const authorizationId = 'authz-' + crypto.randomBytes(8).toString('hex');
        authorizationIds.push(authorizationId);
        database.prepare(
          'INSERT INTO ca_authorizations (authz_id, order_id, identifier, status) VALUES (?, ?, ?, ?)'
        ).run(authorizationId, orderId, identifier.value, 'pending');
        const token = crypto.randomBytes(16).toString('base64url').replace(/=/g, '');
        const keyAuthorization = token + '.' + thumbprint;
        const challengeId = 'chall-' + crypto.randomBytes(8).toString('hex');
        database.prepare(
          'INSERT INTO ca_challenges (challenge_id, authz_id, type, token, key_authorization, status) VALUES (?, ?, ?, ?, ?, ?)'
        ).run(challengeId, authorizationId, 'http-01', token, keyAuthorization, 'pending');
      }

      const authorizationUrls = authorizationIds.map((authorizationId) => baseUrl + '/acme/authz/' + authorizationId);
      return new Response(
        JSON.stringify({
          status: 'pending',
          identifiers,
          authorizations: authorizationUrls,
          finalize: baseUrl + '/acme/finalize/' + orderId,
        }),
        {
          status: 201,
          headers: {
            'Content-Type': 'application/json',
            'Replay-Nonce': generateNonce(),
            Location: baseUrl + '/acme/order/' + orderId,
          },
        }
      );
    }

    const challengePathMatch = pathname.match(/^\/acme\/chall\/([^/]+)$/);
    if (challengePathMatch) {
      const challengeId = challengePathMatch[1]!;
      logger.debug('acme challenge validate', { challengeId });
      const challengeRow = database
        .prepare('SELECT authz_id, token, key_authorization, status FROM ca_challenges WHERE challenge_id = ?')
        .get(challengeId) as { authz_id: string; token: string; key_authorization: string; status: string } | undefined;
      if (!challengeRow) {
        return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 404 });
      }
      const authorizationRow = database
        .prepare('SELECT identifier FROM ca_authorizations WHERE authz_id = ?')
        .get(challengeRow.authz_id) as { identifier: string };
      const domain = authorizationRow.identifier;

      // Bereits per „Manuell annehmen“ oder vorherigen Lauf validiert → sofort Erfolg
      if (challengeRow.status === 'valid') {
        logger.debug('acme challenge already valid', { domain });
        const authzUrl = baseUrl + '/acme/authz/' + challengeRow.authz_id;
        const linkUp = `<${authzUrl}>; rel="up"`;
        return new Response(
          JSON.stringify({
            type: 'http-01',
            status: 'valid',
            token: challengeRow.token,
            url: url.origin + url.pathname,
          }),
          { headers: { 'Content-Type': 'application/json', 'Replay-Nonce': generateNonce(), Link: linkUp } }
        );
      }

      const valid = await runChallengeValidation(database, challengeId);
      const authzUrl = baseUrl + '/acme/authz/' + challengeRow.authz_id;
      const linkUp = `<${authzUrl}>; rel="up"`;
      if (valid) {
        return new Response(
          JSON.stringify({
            type: 'http-01',
            status: 'valid',
            token: challengeRow.token,
            url: url.origin + url.pathname,
          }),
          { headers: { 'Content-Type': 'application/json', 'Replay-Nonce': generateNonce(), Link: linkUp } }
        );
      }
      return Response.json({ type: 'urn:ietf:params:acme:error:incorrectResponse' }, { status: 400 });
    }

    const finalizePathMatch = pathname.match(/^\/acme\/finalize\/([^/]+)$/);
    if (finalizePathMatch) {
      const orderId = finalizePathMatch[1]!;
      logger.debug('acme finalize', { orderId });
      try {
        const orderRow = database
          .prepare('SELECT order_id, identifiers, status, cert_id FROM ca_orders WHERE order_id = ?')
          .get(orderId) as { order_id: string; identifiers: string; status: string; cert_id: number | null } | undefined;
        if (!orderRow) {
          return Response.json({ type: 'urn:ietf:params:acme:error:malformed', detail: 'Order not found' }, { status: 404 });
        }
        if (orderRow.status === 'valid' && orderRow.cert_id != null) {
          return new Response(
            JSON.stringify({ status: 'valid', certificate: baseUrl + '/acme/cert/' + orderId }),
            {
              headers: {
                'Content-Type': 'application/json',
                'Replay-Nonce': generateNonce(),
                Location: baseUrl + '/acme/order/' + orderId,
              },
            }
          );
        }
        if (orderRow.status !== 'ready' && orderRow.status !== 'pending') {
          return Response.json({ type: 'urn:ietf:params:acme:error:orderNotReady', detail: 'Order not ready to finalize' }, { status: 400 });
        }

        const csrBase64 = payload.csr as string;
        if (!csrBase64) {
          return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 400 });
        }
        const csrDer = Buffer.from(csrBase64, 'base64url');
        const base64Lines = csrDer.toString('base64').match(/.{1,64}/g);
        if (!base64Lines || base64Lines.length === 0) {
          return Response.json({ type: 'urn:ietf:params:acme:error:badCSR', detail: 'Invalid CSR encoding' }, { status: 400 });
        }
        const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\n' + base64Lines.join('\n') + '\n-----END CERTIFICATE REQUEST-----';
        let csr: forge.pki.CertificationRequest;
        try {
          csr = forge.pki.certificationRequestFromPem(csrPem);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          logger.debug('acme finalize CSR parse failed', { error: msg });
          if (msg.includes('not RSA') || msg.includes('OID is not RSA')) {
            return Response.json(
              {
                type: 'urn:ietf:params:acme:error:badCSR',
                detail: 'This CA only supports RSA keys. Use certbot with --key-type rsa (e.g. certbot certonly --manual ... --key-type rsa).',
              },
              { status: 400 }
            );
          }
          return Response.json({ type: 'urn:ietf:params:acme:error:badCSR', detail: 'Invalid CSR' }, { status: 400 });
        }
        if (!csr.verify()) {
          return Response.json({ type: 'urn:ietf:params:acme:error:badCSR' }, { status: 400 });
        }

        const certificate = forge.pki.createCertificate();
        certificate.publicKey = csr.publicKey;
        certificate.serialNumber = String(Date.now());
        certificate.validity.notBefore = new Date();
        certificate.validity.notAfter = new Date();
        certificate.validity.notAfter.setFullYear(certificate.validity.notAfter.getFullYear() + 1);
        certificate.setSubject(csr.subject.attributes);

        const rootCa = getCa(database, paths);
        if (!rootCa) {
          return Response.json({ type: 'urn:ietf:params:acme:error:serverInternal' }, { status: 503 });
        }
        const activeCaId = getActiveCaId(database);
        const firstIntermediate = activeCaId
          ? (database.prepare('SELECT id FROM intermediate_cas WHERE parent_ca_id = ? LIMIT 1').get(activeCaId) as { id: string } | undefined)
          : undefined;
        const signer = firstIntermediate
          ? getSignerCa(database, paths, firstIntermediate.id)
          : rootCa;
        certificate.setIssuer(signer.cert.subject.attributes);
        certificate.sign(signer.key, forge.md.sha256.create());

        const leafPem = forge.pki.certificateToPem(certificate);
        const intermediatePem = firstIntermediate ? forge.pki.certificateToPem(signer.cert) : '';
        const rootPem = forge.pki.certificateToPem(rootCa.cert);
        const chainPem = firstIntermediate ? `${leafPem}${intermediatePem}${rootPem}` : `${leafPem}${rootPem}`;
        const insertResult = database.prepare('INSERT INTO ca_certificates (order_id, pem) VALUES (?, ?)').run(orderId, chainPem);
        const certificateRowId = insertResult.lastInsertRowid as number;
        database.prepare('UPDATE ca_orders SET status = ?, cert_id = ? WHERE order_id = ?').run('valid', certificateRowId, orderId);

        const domainList = JSON.parse(orderRow.identifiers) as Array<{ value: string }>;
        const notAfter = certificate.validity.notAfter.toISOString();
        const issuerIdForCert = firstIntermediate ? firstIntermediate.id : activeCaId ?? null;
        for (const domainEntry of domainList) {
          database.prepare('INSERT INTO certificates (domain, not_after, issuer_id, ca_certificate_id) VALUES (?, ?, ?, ?)').run(
            domainEntry.value,
            notAfter,
            issuerIdForCert,
            certificateRowId
          );
        }

        return new Response(
          JSON.stringify({ status: 'valid', certificate: baseUrl + '/acme/cert/' + orderId }),
          {
            headers: {
              'Content-Type': 'application/json',
              'Replay-Nonce': generateNonce(),
              Location: baseUrl + '/acme/order/' + orderId,
            },
          }
        );
      } catch (err) {
        logger.debug('acme finalize error', { error: String(err), stack: err instanceof Error ? err.stack : undefined });
        return Response.json(
          { type: 'urn:ietf:params:acme:error:serverInternal', detail: err instanceof Error ? err.message : 'Finalize failed' },
          { status: 500 }
        );
      }
    }

    const authzPostMatch = pathname.match(/^\/acme\/authz\/([^/]+)$/);
    if (authzPostMatch && requestUrl === baseUrl + '/acme/authz/' + authzPostMatch[1]) {
      const authorizationId = authzPostMatch[1]!;
      logger.debug('acme authz POST', { authorizationId });
      const authorizationRow = database
        .prepare('SELECT authz_id, order_id, identifier, status FROM ca_authorizations WHERE authz_id = ?')
        .get(authorizationId) as { authz_id: string; order_id: string; identifier: string; status: string } | undefined;
      if (!authorizationRow) {
        return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 404 });
      }
      const challengeRows = database
        .prepare('SELECT challenge_id, type, token, status FROM ca_challenges WHERE authz_id = ?')
        .all(authorizationId) as Array<{ challenge_id: string; type: string; token: string; status: string }>;
      const challengeObjects = challengeRows.map((challenge) => ({
        type: challenge.type,
        token: challenge.token,
        status: challenge.status,
        url: baseUrl + '/acme/chall/' + challenge.challenge_id,
      }));
      return new Response(
        JSON.stringify({
          status: authorizationRow.status,
          identifier: { type: 'dns', value: authorizationRow.identifier },
          challenges: challengeObjects,
        }),
        { headers: { 'Content-Type': 'application/json', 'Replay-Nonce': generateNonce() } }
      );
    }

    const certPostMatch = pathname.match(/^\/acme\/cert\/([^/]+)$/);
    if (certPostMatch) {
      const orderId = certPostMatch[1]!;
      logger.debug('acme cert POST-as-GET', { orderId });
      const certificateRow = database
        .prepare('SELECT pem FROM ca_certificates WHERE order_id = ?')
        .get(orderId) as { pem: string } | undefined;
      if (!certificateRow) {
        return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 404 });
      }
      const linkUp = `<${baseUrl}/acme/ca>; rel="up"`;
      return new Response(certificateRow.pem, {
        headers: {
          'Content-Type': 'application/pem-certificate-chain',
          Link: linkUp,
          'Replay-Nonce': generateNonce(),
        },
      });
    }

    const orderPostMatch = pathname.match(/^\/acme\/order\/([^/]+)$/);
    if (orderPostMatch) {
      const orderId = orderPostMatch[1]!;
      logger.debug('acme order POST-as-GET', { orderId });
      const orderRow = database
        .prepare('SELECT order_id, account_id, identifiers, status, finalize_url, cert_id FROM ca_orders WHERE order_id = ?')
        .get(orderId) as
        | { order_id: string; account_id: string; identifiers: string; status: string; finalize_url: string; cert_id: number | null }
        | undefined;
      if (!orderRow) {
        return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 404 });
      }
      const authzRows = database
        .prepare('SELECT authz_id FROM ca_authorizations WHERE order_id = ?')
        .all(orderId) as Array<{ authz_id: string }>;
      const authorizationUrls = authzRows.map((r) => baseUrl + '/acme/authz/' + r.authz_id);
      const orderBody: Record<string, unknown> = {
        status: orderRow.status,
        identifiers: JSON.parse(orderRow.identifiers),
        authorizations: authorizationUrls,
        finalize: orderRow.finalize_url,
      };
      if (orderRow.status === 'valid' && orderRow.cert_id != null) {
        orderBody.certificate = baseUrl + '/acme/cert/' + orderId;
      }
      return new Response(JSON.stringify(orderBody), {
        headers: { 'Content-Type': 'application/json', 'Replay-Nonce': generateNonce() },
      });
    }
  }

  const authzPathMatch = pathname.match(/^\/acme\/authz\/([^/]+)$/);
  if (authzPathMatch && request.method === 'GET') {
    const authorizationId = authzPathMatch[1]!;
    logger.debug('acme authz GET', { authorizationId });
    const authorizationRow = database
      .prepare('SELECT authz_id, order_id, identifier, status FROM ca_authorizations WHERE authz_id = ?')
      .get(authorizationId) as { authz_id: string; order_id: string; identifier: string; status: string } | undefined;
    if (!authorizationRow) {
      return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 404 });
    }
    const challengeRows = database
      .prepare('SELECT challenge_id, type, token, status FROM ca_challenges WHERE authz_id = ?')
      .all(authorizationId) as Array<{ challenge_id: string; type: string; token: string; status: string }>;
    const challengeObjects = challengeRows.map((challenge) => ({
      type: challenge.type,
      token: challenge.token,
      status: challenge.status,
      url: baseUrl + '/acme/chall/' + challenge.challenge_id,
    }));
    return Response.json({
      status: authorizationRow.status,
      identifier: { type: 'dns', value: authorizationRow.identifier },
      challenges: challengeObjects,
    });
  }

  if (pathname === '/acme/ca' && request.method === 'GET') {
    logger.debug('acme ca GET');
    const ca = getCa(database, paths);
    if (!ca) {
      return new Response(null, { status: 404 });
    }
    const caPem = forge.pki.certificateToPem(ca.cert);
    const linkUp = `<${baseUrl}/acme/ca>; rel="up"`;
    return new Response(caPem, {
      headers: {
        'Content-Type': 'application/pem-certificate-chain',
        Link: linkUp,
      },
    });
  }

  const certPathMatch = pathname.match(/^\/acme\/cert\/([^/]+)$/);
  if (certPathMatch && request.method === 'GET') {
    const orderId = certPathMatch[1]!;
    logger.debug('acme cert GET', { orderId });
    const certificateRow = database
      .prepare('SELECT pem FROM ca_certificates WHERE order_id = ?')
      .get(orderId) as { pem: string } | undefined;
    if (!certificateRow) {
      return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 404 });
    }
    const linkUp = `<${baseUrl}/acme/ca>; rel="up"`;
    return new Response(certificateRow.pem, {
      headers: {
        'Content-Type': 'application/pem-certificate-chain',
        Link: linkUp,
      },
    });
  }

  logger.debug('acme no match', { pathname, method: request.method });
  return new Response('Not found', { status: 404 });
}
