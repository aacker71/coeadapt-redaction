/**
 * Inlined seed taxonomy for the semantic redactor.
 *
 * Lifted from career-box-dev/src/main/privacy/taxonomy/seed.json and inlined as
 * a module constant so the package has no runtime file I/O and ships portably
 * (no `fs`, no bundler asset-copy step, no fetch-and-execute path).
 *
 * Maps proper nouns to generic class placeholders. Matching is case-insensitive
 * on whole-word boundaries; multi-word terms ("Goldman Sachs") match as a unit.
 * Updates ship with the package, not via a runtime feed.
 */
export interface TaxonomySeed {
    version: number;
    categories: Record<string, Record<string, string>>;
}
export declare const SEED_TAXONOMY: TaxonomySeed;
//# sourceMappingURL=taxonomy.d.ts.map