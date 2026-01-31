/**
 * Zentrale Konstanten und Defaults.
 * Eine aktive CA: Der Wert unter CONFIG_KEY_ACTIVE_CA_ID bestimmt, welche Root-CA
 * für den ACME-Server verwendet wird. Es gibt genau eine aktive CA.
 */
export const CONFIG_KEY_ACTIVE_CA_ID = 'active_ca_id';

/** Default Common Name für Root-CA (Formulare, API, DB). */
export const DEFAULT_COMMON_NAME_ROOT = 'Cert Manager CA';

/** Default Common Name für Intermediate-CA. */
export const DEFAULT_COMMON_NAME_INTERMEDIATE = 'Intermediate CA';

/** Name der CA bei Migration alter Einzel-CA-Dateien (default) in die cas-Tabelle. */
export const DEFAULT_CA_NAME_MIGRATION = 'Default CA';

/** Default RSA-Schlüssellänge (Bit). */
export const DEFAULT_KEY_SIZE = 2048;

/** Default Gültigkeit Root/Intermediate (Jahre). */
export const DEFAULT_VALIDITY_YEARS = 10;

/** Default Gültigkeit Leaf-Zertifikat (Tage). */
export const DEFAULT_VALIDITY_DAYS = 365;

/** Default Hash-Algorithmus für Signaturen. */
export const DEFAULT_HASH_ALGORITHM = 'sha256';

/** Erlaubte Hash-Algorithmen (für Validierung/UI). */
export const HASH_ALGORITHMS = ['sha256', 'sha384', 'sha512'] as const;

/** Erlaubte Schlüssellängen (Bit). */
export const KEY_SIZES = [2048, 4096] as const;
