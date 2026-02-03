import type { Database } from 'bun:sqlite';
import type { PathHelpers } from './paths.js';
import { handleAcmeChallenge } from './acme-challenge.js';
import { handleAcme } from './acme.js';
import { handleApi } from './api.js';
import { logger } from './logger.js';

export type RenderDashboard = (database: Database, paths: PathHelpers) => Response;

export function createRequestHandler(
  database: Database,
  paths: PathHelpers,
  port: number,
  renderDashboard: RenderDashboard
): (request: Request) => Promise<Response> {
  return async function handleRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    logger.debug('request', { method, pathname, host: request.headers.get('host') ?? undefined });

    const today = new Date().toISOString().slice(0, 10);
    try {
      database.prepare('INSERT INTO request_stats (date, count) VALUES (?, 1) ON CONFLICT(date) DO UPDATE SET count = count + 1').run(today);
    } catch {
      // ignore
    }

    let response: Response;

    if (pathname.startsWith('/.well-known/acme-challenge/')) {
      const r = handleAcmeChallenge(database, request);
      response = r ?? new Response('Not found', { status: 404 });
    } else if (pathname.startsWith('/acme/')) {
      response = await handleAcme(database, paths, port, request);
    } else if (pathname.startsWith('/api/')) {
      response = await handleApi(database, paths, request);
    } else if (pathname === '/') {
      response = renderDashboard(database, paths);
    } else {
      response = new Response('Not found', { status: 404 });
    }

    logger.debug('response', { method, pathname, status: response.status });
    return response;
  };
}
