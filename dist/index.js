/**
 * @coeadapt/redaction — shared PII redaction firewall.
 *
 * Single source of truth for every TypeScript egress path in the Coeadapt
 * portfolio pipeline. See README for which path uses which export.
 */
export { PII_PATTERNS, SENSITIVITY_HINTS, SEVERITY_RANK, } from './pii-patterns.js';
export { scrub, scrubAtIngest, containsPii, } from './redactor-deterministic.js';
export { scrubSemantic, resetTaxonomyForTests, } from './redactor-semantic.js';
export { Redactor, } from './redact-fields.js';
export { SEED_TAXONOMY } from './taxonomy.js';
//# sourceMappingURL=index.js.map