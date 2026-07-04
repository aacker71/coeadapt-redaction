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
export interface SemanticReplacement {
    originalTerm: string;
    className: string;
    startIndex: number;
}
export interface SemanticScrubResult {
    redacted: string;
    classifications: SemanticReplacement[];
    /** Phase B (not yet implemented): proper nouns outside the taxonomy. */
    unmappedProperNouns: string[];
}
/** Reset the cached taxonomy. Test-only. */
export declare function resetTaxonomyForTests(): void;
/**
 * Replace taxonomy terms in already-deterministically-scrubbed text. Operates on
 * the `redacted` output of `scrub`, never on raw user content. The deterministic
 * stage's `<PLACEHOLDER>` tokens contain no taxonomy terms, so they pass through.
 */
export declare function scrubSemantic(stage1Text: string | null | undefined): SemanticScrubResult;
//# sourceMappingURL=redactor-semantic.d.ts.map