/**
 * Deterministic redactor — pure, no I/O.
 *
 *   raw text ──► [for each pattern at/above the severity threshold]
 *                   ├── match? ──► replace with placeholder + push Replacement
 *                   └── no match? ─► continue
 *                ──► return { redacted, replacements }
 *
 * Patterns are run in declared order so that more-specific credential matchers
 * (Anthropic key, JWT) mask substrings before the GENERIC_API_KEY fallback.
 */

import { PII_PATTERNS, SEVERITY_RANK, type PiiPattern, type PiiSeverity } from './pii-patterns.js';

export interface Replacement {
  /** Pattern name from PII_PATTERNS (stable identifier for the manifest). */
  pattern: string;
  /** Original matched substring — NEVER persist past the redactor's caller. */
  originalSnippet: string;
  /** What it was replaced with. */
  placeholder: string;
  /** Severity at time of redaction. */
  severity: PiiPattern['severity'];
  /** Character offset in the original (post-prior-replacements) text. */
  startIndex: number;
}

export interface ScrubResult {
  redacted: string;
  replacements: Replacement[];
}

export interface ScrubOptions {
  /**
   * Lowest severity to redact. Defaults to 'low' (everything). Set to 'high' to
   * scrub only credentials + government/financial identifiers and leave
   * emails/URLs/hostnames intact.
   */
  minSeverity?: PiiSeverity;
}

/**
 * Apply every PII pattern at/above `minSeverity` to the input. Pure function.
 *
 * The originalSnippet on each Replacement is captured BEFORE later patterns run,
 * so the manifest accurately reflects what was scrubbed at each step.
 */
export function scrub(rawText: string | null | undefined, opts: ScrubOptions = {}): ScrubResult {
  if (!rawText) {
    return { redacted: '', replacements: [] };
  }

  const threshold = SEVERITY_RANK[opts.minSeverity ?? 'low'];
  let redacted = rawText;
  const replacements: Replacement[] = [];

  for (const pattern of PII_PATTERNS) {
    if (SEVERITY_RANK[pattern.severity] < threshold) continue;

    // Reset lastIndex between inputs — defensive; every pattern uses /g.
    pattern.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    let cursor = 0;
    const accum: string[] = [];

    while ((match = pattern.regex.exec(redacted)) !== null) {
      const startIndex = match.index;
      const endIndex = startIndex + match[0].length;

      replacements.push({
        pattern: pattern.name,
        originalSnippet: match[0],
        placeholder: pattern.placeholder,
        severity: pattern.severity,
        startIndex,
      });

      accum.push(redacted.slice(cursor, startIndex), pattern.placeholder);
      cursor = endIndex;

      // Guard against zero-width matches (shouldn't happen with current patterns).
      if (match[0].length === 0) {
        pattern.regex.lastIndex = endIndex + 1;
      }
    }

    if (cursor > 0) {
      accum.push(redacted.slice(cursor));
      redacted = accum.join('');
    }
  }

  return { redacted, replacements };
}

/**
 * @deprecated Use `scrub`. Retained as a named alias so career-box-dev's
 * existing `scrubAtIngest` call sites import cleanly during the migration.
 */
export const scrubAtIngest = scrub;

/**
 * Returns true if any pattern at/above `minSeverity` matches. Cheap path for
 * callers that only need a "should I escalate" signal.
 */
export function containsPii(rawText: string | null | undefined, opts: ScrubOptions = {}): boolean {
  if (!rawText) return false;
  const threshold = SEVERITY_RANK[opts.minSeverity ?? 'low'];
  for (const pattern of PII_PATTERNS) {
    if (SEVERITY_RANK[pattern.severity] < threshold) continue;
    pattern.regex.lastIndex = 0;
    if (pattern.regex.test(rawText)) return true;
  }
  return false;
}
