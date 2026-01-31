import * as crypto from 'node:crypto';
import type { Database } from 'bun:sqlite';
// @ts-expect-error no types
import * as forge from 'node-forge';
import { getCa } from './ca.js';
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

export async function handleAcme(
  database: Database,
  paths: PathHelpers,
  port: number,
  request: Request
): Promise<Response> {
  const url = new URL(request.url);
  const host = request.headers.get('host') ?? `localhost:${port}`;
  const baseUrl = host.startsWith('localhost') ? `http://${host}` : `https://${host}`;
  const pathname = url.pathname;

  if (pathname === '/acme/directory' && request.method === 'GET') {
    return Response.json({
      newNonce: baseUrl + '/acme/new-nonce',
      newAccount: baseUrl + '/acme/new-account',
      newOrder: baseUrl + '/acme/new-order',
    });
  }

  if (pathname === '/acme/new-nonce' && (request.method === 'HEAD' || request.method === 'POST')) {
    return new Response(null, {
      status: 204,
      headers: { 'Replay-Nonce': generateNonce(), 'Cache-Control': 'no-store' },
    });
  }

  if (request.method === 'POST' && pathname.startsWith('/acme/')) {
    const bodyText = await request.text();
    const parsed = await parseJws(bodyText).catch(() => null);
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

    if (requestUrl === baseUrl + '/acme/new-account') {
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
      const challengeRow = database
        .prepare('SELECT authz_id, token, key_authorization FROM ca_challenges WHERE challenge_id = ?')
        .get(challengeId) as { authz_id: string; token: string; key_authorization: string } | undefined;
      if (!challengeRow) {
        return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 404 });
      }
      const authorizationRow = database
        .prepare('SELECT identifier FROM ca_authorizations WHERE authz_id = ?')
        .get(challengeRow.authz_id) as { identifier: string };
      const domain = authorizationRow.identifier;
      try {
        const challengeResponse = await fetch(`http://${domain}/.well-known/acme-challenge/${challengeRow.token}`);
        const responseText = (await challengeResponse.text()).trim();
        if (responseText !== challengeRow.key_authorization) throw new Error('invalid');
      } catch {
        return Response.json({ type: 'urn:ietf:params:acme:error:incorrectResponse' }, { status: 400 });
      }
      database.prepare('UPDATE ca_challenges SET status = ? WHERE challenge_id = ?').run('valid', challengeId);
      database.prepare('UPDATE ca_authorizations SET status = ? WHERE authz_id = ?').run('valid', challengeRow.authz_id);
      return new Response(
        JSON.stringify({
          type: 'http-01',
          status: 'valid',
          token: challengeRow.token,
          url: url.origin + url.pathname,
        }),
        { headers: { 'Content-Type': 'application/json', 'Replay-Nonce': generateNonce() } }
      );
    }

    if (requestUrl?.startsWith(baseUrl + '/acme/finalize/')) {
      const orderId = requestUrl.replace(baseUrl + '/acme/finalize/', '');
      const csrBase64 = payload.csr as string;
      if (!csrBase64) {
        return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 400 });
      }
      const csrDer = Buffer.from(csrBase64, 'base64url');
      const base64Lines = csrDer.toString('base64').match(/.{1,64}/g)!;
      const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\n' + base64Lines.join('\n') + '\n-----END CERTIFICATE REQUEST-----';
      const csr = forge.pki.certificationRequestFromPem(csrPem);
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

      const ca = getCa(database, paths);
      if (!ca) {
        return Response.json({ type: 'urn:ietf:params:acme:error:serverInternal' }, { status: 503 });
      }
      certificate.setIssuer(ca.cert.subject.attributes);
      certificate.sign(ca.key, forge.md.sha256.create());

      const certificatePem = forge.pki.certificateToPem(certificate);
      const insertResult = database.prepare('INSERT INTO ca_certificates (order_id, pem) VALUES (?, ?)').run(orderId, certificatePem);
      const certificateRowId = insertResult.lastInsertRowid as number;
      database.prepare('UPDATE ca_orders SET status = ?, cert_id = ? WHERE order_id = ?').run('valid', certificateRowId, orderId);

      const orderRow = database.prepare('SELECT identifiers FROM ca_orders WHERE order_id = ?').get(orderId) as { identifiers: string };
      const notAfter = certificate.validity.notAfter.toISOString();
      const domainList = JSON.parse(orderRow.identifiers) as Array<{ value: string }>;
      for (const domainEntry of domainList) {
        database.prepare('INSERT INTO certificates (domain, not_after) VALUES (?, ?)').run(domainEntry.value, notAfter);
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
    }
  }

  const authzPathMatch = pathname.match(/^\/acme\/authz\/([^/]+)$/);
  if (authzPathMatch && request.method === 'GET') {
    const authorizationId = authzPathMatch[1]!;
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

  const certPathMatch = pathname.match(/^\/acme\/cert\/([^/]+)$/);
  if (certPathMatch && request.method === 'GET') {
    const orderId = certPathMatch[1]!;
    const certificateRow = database
      .prepare('SELECT pem FROM ca_certificates WHERE order_id = ?')
      .get(orderId) as { pem: string } | undefined;
    if (!certificateRow) {
      return Response.json({ type: 'urn:ietf:params:acme:error:malformed' }, { status: 404 });
    }
    return new Response(certificateRow.pem, {
      headers: { 'Content-Type': 'application/pem-certificate-chain' },
    });
  }

  return new Response('Not found', { status: 404 });
}
