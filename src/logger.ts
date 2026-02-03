import winston from 'winston';
import type { Database } from 'bun:sqlite';

const level = process.env.LOG_LEVEL ?? 'debug';
const MAX_LOG_LINES = 500;

const logLines: string[] = [];
const streamClients: Set<(line: string) => void> = new Set();

/** Baut die komplette Logzeile (wie printf im Logger), damit Terminal/DB Timestamp + Level + Meta anzeigen. */
function formatLogLine(info: Record<string, unknown>): string {
  const timestamp = (info.timestamp as string) ?? '';
  const level = String((info.level as string) ?? 'info').toUpperCase();
  const message = String((info.message as string) ?? '');
  const keys = Object.keys(info).filter((k) => k !== 'timestamp' && k !== 'level' && k !== 'message');
  const metaStr = keys.length ? ' ' + JSON.stringify(Object.fromEntries(keys.map((k) => [k, info[k]]))) : '';
  return `${timestamp} [${level}] ${message}${metaStr}`;
}

function pushLogLine(line: string): void {
  logLines.push(line);
  if (logLines.length > MAX_LOG_LINES) logLines.shift();
  streamClients.forEach((send) => {
    try {
      send(line);
    } catch {
      // ignore
    }
  });
}

class MemoryTransport extends winston.Transport {
  log(info: Record<string, unknown>, callback: () => void): void {
    pushLogLine(formatLogLine(info));
    callback();
  }
}

function createDbTransport(database: Database): winston.Transport {
  return new (class DbTransport extends winston.Transport {
    log(info: Record<string, unknown>, callback: () => void): void {
      const line = formatLogLine(info);
      const timestamp = (info.timestamp as string) ?? new Date().toISOString();
      try {
        database.prepare('INSERT INTO log_entries (created_at, line) VALUES (?, ?)').run(timestamp, line);
      } catch {
        // ignore DB errors (e.g. readonly)
      }
      callback();
    }
  })({ level });
}

/**
 * Initializes the logger with database persistence: loads last N lines from DB into the in-memory buffer
 * and adds a transport that writes new log entries to the database. Call once after database is ready.
 */
export function initLogger(database: Database): void {
  try {
    const rows = database
      .prepare('SELECT created_at, line FROM log_entries ORDER BY id DESC LIMIT ?')
      .all(MAX_LOG_LINES) as Array<{ created_at: string; line: string }>;
    logLines.length = 0;
    for (let i = rows.length - 1; i >= 0; i--) {
      logLines.push(rows[i].line);
    }
  } catch {
    // ignore (e.g. table not yet created)
  }
  logger.add(createDbTransport(database));
}

export function getLogLines(): string[] {
  return [...logLines];
}

export function addLogStreamClient(send: (line: string) => void): () => void {
  streamClients.add(send);
  return () => {
    streamClients.delete(send);
  };
}

export const logger = winston.createLogger({
  level,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ level: l, message, timestamp, ...meta }) => {
      const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
      return `${timestamp} [${l.toUpperCase()}] ${message}${metaStr}`;
    })
  ),
  transports: [
    new winston.transports.Console({ level }),
    new MemoryTransport({ level }),
  ],
});
