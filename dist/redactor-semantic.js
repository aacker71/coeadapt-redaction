/**
 * Semantic redactor — taxonomy-based, runs AFTER the deterministic scrub.
 *
 * Replaces known proper nouns (companies, tools, skills, locations) with generic
 * class placeholders from a hand-curated taxonomy. Cloud-egress only: this would
 * gut a public portfolio, so the portfolio path never runs it.
 *
 *   stage-1 text ──► [longest taxonomy terms first]
 *                      ├── term match? ──► replace with <class>
 *                      └── (Phase B placeholder: unmapped proper nouns)
 *                    ──► { redacted, classifications, unmappedProperNouns }
 *
 * Non-goals: LLM-assisted disambiguation (the model we protect from raw text
 * cannot also be the redactor); live taxonomy fetch.
 */
import { SEED_TAXONOMY } from './taxonomy.js';
let TAXONOMY = null;
function loadTaxonomy() {
    if (TAXONOMY)
        return TAXONOMY;
    const termToClass = new Map();
    for (const category of Object.values(SEED_TAXONOMY.categories)) {
        for (const [term, className] of Object.entries(category)) {
            termToClass.set(term.toLowerCase(), className);
        }
    }
    // "Goldman Sachs" must match before "Sachs".
    const termsByLength = Array.from(termToClass.keys()).sort((a, b) => b.length - a.length);
    TAXONOMY = { termToClass, termsByLength };
    return TAXONOMY;
}
/** Reset the cached taxonomy. Test-only. */
export function resetTaxonomyForTests() {
    TAXONOMY = null;
}
/**
 * Replace taxonomy terms in already-deterministically-scrubbed text. Operates on
 * the `redacted` output of `scrub`, never on raw user content. The deterministic
 * stage's `<PLACEHOLDER>` tokens contain no taxonomy terms, so they pass through.
 */
export function scrubSemantic(stage1Text) {
    if (!stage1Text) {
        return { redacted: '', classifications: [], unmappedProperNouns: [] };
    }
    const tax = loadTaxonomy();
    let redacted = stage1Text;
    const classifications = [];
    // Longest term first so multi-word terms win over their components.
    for (const term of tax.termsByLength) {
        const className = tax.termToClass.get(term);
        const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp(`\\b${escaped}\\b`, 'gi');
        redacted = redacted.replace(re, (match, offset) => {
            classifications.push({ originalTerm: match, className, startIndex: offset });
            return `<${className}>`;
        });
    }
    // Phase B is intentionally a no-op for now — measured by the redactor eval
    // before deciding whether deterministic + taxonomy is sufficient or NER (T5)
    // is needed.
    const unmappedProperNouns = [];
    return { redacted, classifications, unmappedProperNouns };
}
//# sourceMappingURL=redactor-semantic.js.map