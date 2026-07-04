/**
 * Shared PII regex library.
 *
 * Single source of truth for the deterministic redactor (redactor-deterministic)
 * and the field-level firewall (redact-fields). Mirrored — by hand, under a
 * parity test — by `career-box-dev/local_runtime/redaction.py` (Python cannot
 * import this package).
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
 */
/** Numeric rank for severity thresholding (higher = more sensitive). */
export const SEVERITY_RANK = {
    critical: 3,
    high: 2,
    medium: 1,
    low: 0,
};
// ---------------------------------------------------------------------------
// Critical — credentials and keys
// ---------------------------------------------------------------------------
const PEM_KEY = {
    name: 'pem-private-key',
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    placeholder: '<PEM_KEY>',
    severity: 'critical',
};
const ANTHROPIC_API_KEY = {
    name: 'anthropic-api-key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g,
    placeholder: '<ANTHROPIC_KEY>',
    severity: 'critical',
};
const OPENAI_API_KEY = {
    name: 'openai-api-key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g,
    placeholder: '<OPENAI_KEY>',
    severity: 'critical',
};
const GENERIC_API_KEY = {
    // Catch-all for sk- / pk- / ak- / tok- prefixed long alphanum tokens.
    // The Anthropic + OpenAI patterns above are more specific and run first.
    name: 'generic-api-key-prefix',
    regex: /\b(?:sk|pk|ak|tok)-[A-Za-z0-9_-]{16,}\b/g,
    placeholder: '<API_KEY>',
    severity: 'critical',
};
const GITHUB_TOKEN = {
    name: 'github-token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    placeholder: '<GITHUB_TOKEN>',
    severity: 'critical',
};
const AWS_ACCESS_KEY = {
    // AKIA / ASIA + 16 uppercase alphanumerics — AWS access key id.
    name: 'aws-access-key',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    placeholder: '<AWS_ACCESS_KEY>',
    severity: 'critical',
};
const BEARER_TOKEN = {
    name: 'bearer-token',
    regex: /Bearer\s+[A-Za-z0-9._-]{20,}/gi,
    placeholder: 'Bearer <TOKEN>',
    severity: 'critical',
};
const JWT_TOKEN = {
    // Three base64url segments separated by dots, each 8+ chars.
    name: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    placeholder: '<JWT>',
    severity: 'critical',
};
// ---------------------------------------------------------------------------
// High — government / financial identifiers
// ---------------------------------------------------------------------------
const US_SSN = {
    name: 'us-ssn',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    placeholder: '<SSN>',
    severity: 'high',
};
const CREDIT_CARD_LIKE = {
    // Heuristic: 13-19 digits in a contiguous run. Loose by design — false
    // positives (long order numbers, etc.) are acceptable since over-redaction
    // is safe on every egress path this firewall guards.
    name: 'credit-card-like',
    regex: /\b\d{13,19}\b/g,
    placeholder: '<CC>',
    severity: 'high',
};
const EMAIL_PASSWORD_PROXIMITY = {
    // Email followed within ~80 chars by password/passwd/pwd — strong signal
    // that a credential dump is in flight.
    name: 'email-near-password',
    regex: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b[\s\S]{0,80}\b(password|passwd|pwd)\b/gi,
    placeholder: '<EMAIL_PASSWORD_PAIR>',
    severity: 'high',
};
// ---------------------------------------------------------------------------
// Medium — contact identifiers
// ---------------------------------------------------------------------------
const EMAIL = {
    name: 'email',
    regex: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g,
    placeholder: '<EMAIL>',
    severity: 'medium',
};
const US_PHONE = {
    name: 'us-phone',
    regex: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g,
    placeholder: '<PHONE>',
    severity: 'medium',
};
const POSIX_PATH = {
    name: 'posix-home-path',
    regex: /\/(?:home|Users)\/[\w.-]+(?:\/[\w./-]+)?/g,
    placeholder: '<HOME_PATH>',
    severity: 'medium',
};
const WINDOWS_PATH = {
    name: 'windows-user-path',
    regex: /[A-Za-z]:\\Users\\[\w.-]+(?:\\[\w. -]+)*/g,
    placeholder: '<USER_PATH>',
    severity: 'medium',
};
const FQDN = {
    // Bare host names: at least three labels (e.g. prod-db.acme.com). Two-label
    // hosts (foo.com) are deliberately NOT matched — too many false positives on
    // filenames, version strings, class names.
    name: 'fqdn-three-plus-labels',
    regex: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,24}\b/gi,
    placeholder: '<HOSTNAME>',
    severity: 'medium',
};
const CLI_USERNAME_FLAG = {
    // Common CLI patterns that expose usernames: -u/--user/-U <name>.
    name: 'cli-username-flag',
    regex: /(?<=--user[=\s]+|-[uU]\s+)[\w.-]+/g,
    placeholder: '<USER>',
    severity: 'medium',
};
// ---------------------------------------------------------------------------
// Low — network identifiers
// ---------------------------------------------------------------------------
const IPV4 = {
    name: 'ipv4',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    placeholder: '<IP>',
    severity: 'low',
};
const URL = {
    // http(s)://host[/path]. The semantic stage may re-route based on the host's
    // taxonomy class.
    name: 'url',
    regex: /\bhttps?:\/\/[^\s<>"']+/g,
    placeholder: '<URL>',
    severity: 'low',
};
// ---------------------------------------------------------------------------
// Ordered registry — order matters when patterns overlap.
//
// Run 'critical' patterns first so credentials are masked before the generic
// API-key fallback fires. EMAIL_PASSWORD_PROXIMITY runs before EMAIL so the
// stronger compound match wins.
// ---------------------------------------------------------------------------
export const PII_PATTERNS = [
    PEM_KEY,
    ANTHROPIC_API_KEY,
    OPENAI_API_KEY,
    GITHUB_TOKEN,
    AWS_ACCESS_KEY,
    BEARER_TOKEN,
    JWT_TOKEN,
    GENERIC_API_KEY,
    US_SSN,
    EMAIL_PASSWORD_PROXIMITY,
    CREDIT_CARD_LIKE,
    EMAIL,
    US_PHONE,
    WINDOWS_PATH,
    POSIX_PATH,
    URL,
    FQDN,
    CLI_USERNAME_FLAG,
    IPV4,
];
/** Patterns considered 'pii' for sensitivity escalation (critical + high). */
export const SENSITIVITY_HINTS = PII_PATTERNS.filter((p) => p.severity === 'critical' || p.severity === 'high');
//# sourceMappingURL=pii-patterns.js.map