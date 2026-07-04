import { describe, it, expect, beforeEach } from 'vitest';
import { scrubSemantic, resetTaxonomyForTests } from '../src/redactor-semantic';

beforeEach(() => resetTaxonomyForTests());

describe('scrubSemantic — taxonomy replacement (cloud-egress only)', () => {
  it('replaces known companies and tools with class placeholders', () => {
    expect(scrubSemantic('used Stripe and GitHub').redacted).toBe('used <fintech-infra> and <dev-tool>');
  });

  it('matches multi-word terms as a unit (longest-first)', () => {
    expect(scrubSemantic('at Goldman Sachs').redacted).toBe('at <finance-bank>');
  });

  it('is case-insensitive and records classifications', () => {
    const r = scrubSemantic('we use react and POSTGRESQL');
    expect(r.redacted).toBe('we use <frontend-framework> and <database>');
    expect(r.classifications.map((c) => c.className).sort()).toEqual(['database', 'frontend-framework']);
  });

  it('handles dotted terms like Next.js / Node.js', () => {
    expect(scrubSemantic('Next.js on Node.js').redacted).toBe('<frontend-framework> on <runtime>');
  });

  it('passes deterministic placeholders through untouched', () => {
    expect(scrubSemantic('key <AWS_ACCESS_KEY> via GitHub').redacted).toBe('key <AWS_ACCESS_KEY> via <dev-tool>');
  });

  it('handles empty input', () => {
    expect(scrubSemantic('').redacted).toBe('');
    expect(scrubSemantic(null).classifications).toHaveLength(0);
  });
});
