/**
 * Konfiguration (Umgebungsvariablen für Tests überschreibbar).
 */
export function getDataDir(): string {
  return process.env.DATA_DIR ?? './data';
}

export function getDbPath(): string {
  return process.env.DB_PATH ?? './data.db';
}

export function getPort(): number {
  return Number(process.env.PORT ?? 3000);
}

/** Hostname the server listens on (e.g. 0.0.0.0 for all interfaces). */
export function getHostname(): string {
  return process.env.HOST ?? '0.0.0.0';
}
