/**
 * In-Memory-Status für laufende ACME HTTP-01-Validierungen (Polling).
 * Wird vom Dashboard angezeigt (Timer, Zähler) und von acme.ts aktualisiert.
 */
const validationState = new Map<
  string,
  { domain: string; attemptCount: number; maxAttempts: number; nextAttemptAt: number }
>();

const MAX_ATTEMPTS = 5;
const INTERVAL_MS = 5000;

export const ACME_VALIDATION_MAX_ATTEMPTS = MAX_ATTEMPTS;
export const ACME_VALIDATION_INTERVAL_MS = INTERVAL_MS;

export function setValidating(challengeId: string, domain: string): void {
  validationState.set(challengeId, {
    domain,
    attemptCount: 0,
    maxAttempts: MAX_ATTEMPTS,
    nextAttemptAt: Date.now(),
  });
}

export function updateValidationAttempt(
  challengeId: string,
  attemptCount: number,
  success: boolean,
  nextAttemptAt?: number
): void {
  const entry = validationState.get(challengeId);
  if (!entry) return;
  if (success) {
    validationState.delete(challengeId);
    return;
  }
  entry.attemptCount = attemptCount;
  entry.nextAttemptAt = nextAttemptAt ?? Date.now() + INTERVAL_MS;
}

export function clearValidating(challengeId: string): void {
  validationState.delete(challengeId);
}

export function isValidating(challengeId: string): boolean {
  return validationState.has(challengeId);
}

export function getValidationStatus(): Array<{
  challengeId: string;
  domain: string;
  attemptCount: number;
  maxAttempts: number;
  nextAttemptAt: number;
}> {
  const now = Date.now();
  return Array.from(validationState.entries()).map(([challengeId, v]) => ({
    challengeId,
    domain: v.domain,
    attemptCount: v.attemptCount,
    maxAttempts: v.maxAttempts,
    nextAttemptAt: v.nextAttemptAt,
  }));
}
