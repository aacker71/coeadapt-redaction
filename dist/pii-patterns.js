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
 *
 * A pattern may additionally be `detectOnly`: it participates in
 * containsPii / SENSITIVITY_HINTS but is never applied by scrub(). Use this
 * for shapes too ambiguous to rewrite text with (e.g. a bare 9-digit run).
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
    // Heuristic: 13-19 digits with optional single space/dash separators
    // BETWEEN digits, so "4111 1111 1111 1111" and "4111-1111-1111-1111" match
    // as well as the contiguous run (and the match never swallows a trailing
    // separator). Loose by design — false positives (long order numbers, etc.)
    // are acceptable since over-redaction is safe on every egress path this
    // firewall guards. No Luhn check: a card with one mistyped digit should
    // still be caught.
    name: 'credit-card-like',
    regex: /\b\d(?:[ -]?\d){12,18}\b/g,
    placeholder: '<CC>',
    severity: 'high',
};
const FULL_DOB = {
    // d/m or m/d plus a 19xx/20xx year, slash- or dash-separated. Matches any
    // date in that shape, not just birth dates — acceptable over-redaction.
    // ISO dates (2026-07-04) are year-first and do NOT match.
    name: 'full-dob',
    regex: /\b\d{1,2}[/-]\d{1,2}[/-](?:19|20)\d{2}\b/g,
    placeholder: '<DOB>',
    severity: 'high',
};
const PASSPORT_NUMBER = {
    // Keyword-anchored: "passport", optional "no."/"number", then a 6+ char
    // alphanumeric id. Replaces the whole span, keyword included.
    name: 'passport-number',
    regex: /\bpassport(?:\s+no\.?|\s+number)?\s*[:#]?\s*[A-Z0-9]{6,}\b/gi,
    placeholder: '<PASSPORT>',
    severity: 'high',
};
const ROUTING_OR_ACCOUNT_NUMBER = {
    // Keyword-anchored bank identifiers. Runs before CREDIT_CARD_LIKE and
    // US_SSN_NO_SEPARATOR in the registry so "account number 4111111111111111"
    // and "routing number 021000021" get the specific placeholder, not <CC>.
    name: 'routing-or-account-number',
    regex: /\b(?:routing|account)\s*(?:no\.?|number)?[\s:#]*\d{6,}\b/gi,
    placeholder: '<ACCOUNT_NUMBER>',
    severity: 'high',
};
const US_SSN_NO_SEPARATOR = {
    // An SSN written without separators is indistinguishable from any other
    // 9-digit number (order ids, issue numbers, routing numbers), so this is
    // detectOnly: it escalates sensitivity via containsPii/SENSITIVITY_HINTS
    // but scrub() never rewrites the text with it.
    name: 'us-ssn-no-separator',
    regex: /\b\d{9}\b/g,
    placeholder: '<SSN>',
    severity: 'high',
    detectOnly: true,
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
// stronger compound match wins. Keyword-anchored financial patterns
// (PASSPORT_NUMBER, ROUTING_OR_ACCOUNT_NUMBER) run before the loose digit-run
// patterns (CREDIT_CARD_LIKE, US_SSN_NO_SEPARATOR) for the same reason.
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
    PASSPORT_NUMBER,
    ROUTING_OR_ACCOUNT_NUMBER,
    CREDIT_CARD_LIKE,
    FULL_DOB,
    US_SSN_NO_SEPARATOR,
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