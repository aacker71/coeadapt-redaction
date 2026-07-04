/**
 * @coeadapt/redaction — shared PII redaction firewall.
 *
 * Single source of truth for every TypeScript egress path in the Coeadapt
 * portfolio pipeline. See README for which path uses which export.
 */

export {
  PII_PATTERNS,
  SENSITIVITY_HINTS,
  SEVERITY_RANK,
  type PiiPattern,
  type PiiSeverity,
} from './pii-patterns.js';

export {
  scrub,
  scrubAtIngest,
  containsPii,
  type Replacement,
  type ScrubResult,
  type ScrubOptions,
} from './redactor-deterministic.js';

export {
  scrubSemantic,
  resetTaxonomyForTests,
  type SemanticReplacement,
  type SemanticScrubResult,
} from './redactor-semantic.js';

export {
  Redactor,
  type FieldRedaction,
  type RedactionManifest,
  type RedactorOptions,
} from './redact-fields.js';

export { SEED_TAXONOMY, type TaxonomySeed } from './taxonomy.js';
