import type { Database } from 'bun:sqlite';

export function handleAcmeChallenge(
  database: Database,
  request: Request
): Response | null {
  const url = new URL(request.url);
  const tokenMatch = url.pathname.match(/^\/\.well-known\/acme-challenge\/(.+)/);
  const token = tokenMatch?.[1];
  if (!token) return null;

  let keyAuthorization: string | undefined;
  const legacyRow = database
    .prepare('SELECT key_authorization FROM challenges WHERE token = ?')
    .get(token) as { key_authorization: string } | undefined;
  if (legacyRow) keyAuthorization = legacyRow.key_authorization;

  if (!keyAuthorization) {
    const caRow = database
      .prepare('SELECT key_authorization FROM ca_challenges WHERE token = ?')
      .get(token) as { key_authorization: string } | undefined;
    if (caRow) keyAuthorization = caRow.key_authorization;
  }

  if (!keyAuthorization) {
    return new Response('Not found', { status: 404 });
  }

  return new Response(keyAuthorization, {
    headers: { 'Content-Type': 'text/plain' },
  });
}
