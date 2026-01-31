import type { Database } from 'bun:sqlite';

export function handleAcmeChallenge(
  database: Database,
  request: Request
): Response | null {
  const url = new URL(request.url);
  const tokenMatch = url.pathname.match(/^\/\.well-known\/acme-challenge\/(.+)/);
  const token = tokenMatch?.[1];
  if (!token) return null;

  const challengeRow = database
    .prepare('SELECT key_authorization FROM challenges WHERE token = ?')
    .get(token) as { key_authorization: string } | undefined;

  if (!challengeRow) {
    return new Response('Not found', { status: 404 });
  }

  return new Response(challengeRow.key_authorization, {
    headers: { 'Content-Type': 'text/plain' },
  });
}
