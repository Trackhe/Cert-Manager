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

const FAILED_CHALLENGE_COOLDOWN_MS = 20000;
const failedChallengeDomains = new Map<string, number>();

export const ACME_FAILED_CHALLENGE_COOLDOWN_MS = FAILED_CHALLENGE_COOLDOWN_MS;

export function recordChallengeFailed(domain: string): void {
  failedChallengeDomains.set(domain, Date.now());
}

export function getCooldownRemainingMs(domain: string): number {
  const now = Date.now();
  for (const [d, failedAt] of failedChallengeDomains.entries()) {
    if (now - failedAt >= FAILED_CHALLENGE_COOLDOWN_MS) {
      failedChallengeDomains.delete(d);
    }
  }
  const failedAt = failedChallengeDomains.get(domain);
  if (failedAt == null) return 0;
  const elapsed = now - failedAt;
  if (elapsed >= FAILED_CHALLENGE_COOLDOWN_MS) {
    failedChallengeDomains.delete(domain);
    return 0;
  }
  return FAILED_CHALLENGE_COOLDOWN_MS - elapsed;
}

export function getValidationStatus(): Array<{
  challengeId: string;
  domain: string;
  attemptCount: number;
  maxAttempts: number;
  nextAttemptAt: number;
}> {
  return Array.from(validationState.entries()).map(([challengeId, v]) => ({
    challengeId,
    domain: v.domain,
    attemptCount: v.attemptCount,
    maxAttempts: v.maxAttempts,
    nextAttemptAt: v.nextAttemptAt,
  }));
}
