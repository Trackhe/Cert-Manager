import type { Database } from 'bun:sqlite';
import type { PathHelpers } from './paths.js';
import { handleAcmeChallenge } from './acme-challenge.js';
import { handleAcme } from './acme.js';
import { handleApi } from './api.js';

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

    if (pathname.startsWith('/.well-known/acme-challenge/')) {
      const response = handleAcmeChallenge(database, request);
      return response ?? new Response('Not found', { status: 404 });
    }

    if (pathname.startsWith('/acme/')) {
      return handleAcme(database, paths, port, request);
    }

    if (pathname.startsWith('/api/')) {
      return handleApi(database, paths, request);
    }

    if (pathname === '/') {
      return renderDashboard(database, paths);
    }

    return new Response('Not found', { status: 404 });
  };
}
