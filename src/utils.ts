import { existsSync, unlinkSync } from 'node:fs';
import { logger } from './logger.js';

/**
 * Safely deletes a file, logging any errors instead of throwing
 * @param path - Path to the file to delete
 * @param context - Optional context string for logging (e.g., 'certificate key', 'CA file')
 */
export function safeUnlinkSync(path: string, context?: string): void {
  if (!existsSync(path)) {
    return;
  }
  
  try {
    unlinkSync(path);
  } catch (err) {
    const contextStr = context ? ` (${context})` : '';
    logger.warn(`Datei konnte nicht gelöscht werden${contextStr}`, {
      path,
      error: String(err),
    });
  }
}

/**
 * Checks if a domain matches a wildcard pattern (e.g., "*.example.com" matches "sub.example.com")
 * @param domain - The domain to check
 * @param pattern - The pattern to match against (can include wildcard *)
 * @returns true if domain matches the pattern
 */
export function matchesWildcardDomain(domain: string, pattern: string): boolean {
  if (pattern === domain) {
    return true;
  }
  if (pattern.startsWith('*.')) {
    const baseDomain = pattern.slice(2);
    // Matches if domain ends with base domain and has exactly one subdomain level
    return domain.endsWith('.' + baseDomain) && domain.split('.').length === baseDomain.split('.').length + 1;
  }
  return false;
}

/**
 * Safely parses an integer from a string or number, returning null if invalid
 * @param value - The value to parse
 * @returns The parsed integer or null if invalid
 */
export function safeParseInt(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? Math.floor(value) : null;
  }
  if (typeof value === 'string') {
    const parsed = parseInt(value, 10);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

/**
 * Validates that a parsed JSON object has the expected string properties
 * @param obj - The object to validate
 * @param requiredProps - Array of property names that must be strings
 * @returns true if all required properties are present and are strings
 */
export function hasStringProperties(obj: unknown, requiredProps: string[]): boolean {
  if (typeof obj !== 'object' || obj === null) {
    return false;
  }
  const record = obj as Record<string, unknown>;
  return requiredProps.every((prop) => typeof record[prop] === 'string');
}
