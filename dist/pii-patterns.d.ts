/**
 * Shared PII regex library.
 *
 * Single source of truth for the deterministic redactor (redactor-deterministic)
 * and the field-level firewall (redact-fields). Mirrored by hand by
 * `career-box-dev/local_runtime/redaction.py` (Python cannot import this
 * package); agreement is enforced by the shared parity corpus at
 * `career-box-dev/evals/redaction-parity/` (75 adversarial fixtures, run in
 * that repo's CI — measured 2026-07-13: 41/46 critical-class neutralizations
 * on BOTH sides with this commit's patterns, zero TS<->Python disagreements;
 * the 5 remaining misses are documented regex-layer limits in PARITY.md:
 * spaced/base64/chunk-split keys and non-US national ids). Update the corpus
 * when changing any regex here.
 *
 * Patterns MUST be module-level constants so they are compiled exactly once per
 * process. Calling `new RegExp(...)` per event would dominate the hot path.
 *
 * Pattern severity:
 *   - 'critical': must never reach an LLM or the cloud (credentials, PEM keys)
 *   - 'high':     must not leave the local machine (SSN, CC, account numbers)
 *   - 'medium':   redacted by default but acceptable in some contexts
 *                 (emails, phone numbers, file paths, hostnames)
 *   - 'low':      replaceable with a class placeholder (URLs, IP addresses)
 *
 * A pattern may additionally be `detectOnly`: it participates in
 * containsPii / SENSITIVITY_HINTS but is never applied by scrub(). Use this
 * for shapes too ambiguous to rewrite text with (e.g. a bare 9-digit run).
 */
export type PiiSeverity = 'critical' | 'high' | 'medium' | 'low';
export interface PiiPattern {
    /** Stable identifier used in the redaction manifest. */
    readonly name: string;
    /** The compiled regex; module-level so we compile once. */
    readonly regex: RegExp;
    /** Placeholder that replaces a match. */
    readonly placeholder: string;
    /** Trust tier — see file header. */
    readonly severity: PiiSeverity;
    /**
     * Detection-only: counts for `containsPii` / SENSITIVITY_HINTS escalation
     * but is skipped by `scrub`. For patterns too false-positive-prone to
     * rewrite text with (escalating sensitivity on a false positive is cheap;
     * masking a build number as <SSN> on an egress path is not).
     */
    readonly detectOnly?: boolean;
}
/** Numeric rank for severity thresholding (higher = more sensitive). */
export declare const SEVERITY_RANK: Record<PiiSeverity, number>;
export declare const PII_PATTERNS: ReadonlyArray<PiiPattern>;
/** Patterns considered 'pii' for sensitivity escalation (critical + high). */
export declare const SENSITIVITY_HINTS: ReadonlyArray<PiiPattern>;
//# sourceMappingURL=pii-patterns.d.ts.map