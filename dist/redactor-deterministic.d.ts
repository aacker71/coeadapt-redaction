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
import { type PiiPattern, type PiiSeverity } from './pii-patterns.js';
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
export declare function scrub(rawText: string | null | undefined, opts?: ScrubOptions): ScrubResult;
/**
 * @deprecated Use `scrub`. Retained as a named alias so career-box-dev's
 * existing `scrubAtIngest` call sites import cleanly during the migration.
 */
export declare const scrubAtIngest: typeof scrub;
/**
 * Returns true if any pattern at/above `minSeverity` matches. Cheap path for
 * callers that only need a "should I escalate" signal.
 */
export declare function containsPii(rawText: string | null | undefined, opts?: ScrubOptions): boolean;
//# sourceMappingURL=redactor-deterministic.d.ts.map