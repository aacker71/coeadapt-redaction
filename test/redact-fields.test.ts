import { describe, it, expect } from 'vitest';
import { Redactor } from '../src/redact-fields';

describe('Redactor — field-level firewall + manifest', () => {
  it('SMOKING GUN: the open claude-code-plugin bypass — a submission with a secret in description comes back scrubbed', () => {
    // This is exactly the payload the consumer stored VERBATIM before the fix:
    // an un-redacted producer (the plugin has no redactor) puts a live AWS key
    // and an SSN in free text, marks it public.
    const r = new Redactor(); // all severities, semantic OFF (portfolio path)
    const description = r.field(
      'description',
      'Shipped billing. AWS key AKIAIOSFODNN7EXAMPLE, contact 123-45-6789.',
    );

    // The public portfolio now never sees the secret.
    expect(description).toBe('Shipped billing. AWS key <AWS_ACCESS_KEY>, contact <SSN>.');
    expect(description).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(description).not.toContain('123-45-6789');

    // The manifest records WHAT fired, never the secret itself.
    const m = r.manifest();
    expect(m.total).toBe(2);
    expect(m.fields).toHaveLength(1);
    const names = m.fields[0].patterns.map((p) => p.name).sort();
    expect(names).toEqual(['aws-access-key', 'us-ssn']);
    expect(JSON.stringify(m)).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('accumulates a per-field manifest across many fields', () => {
    const r = new Redactor();
    const name = r.field('name', 'Acme Dashboard');
    const detail = r.field('accomplishments[0].detail', 'reduced latency, see me@example.com');

    expect(name).toBe('Acme Dashboard'); // clean field → no manifest entry
    expect(detail).toBe('reduced latency, see <EMAIL>');
    expect(r.touched).toBe(true);
    expect(r.manifest().fields.map((f) => f.field)).toEqual(['accomplishments[0].detail']);
  });

  it('keeps real proper nouns on the portfolio (semantic OFF by default)', () => {
    const r = new Redactor();
    // Real skills/employers must survive — the portfolio is the whole point.
    expect(r.field('description', 'Built with React at Google')).toBe('Built with React at Google');
    expect(r.touched).toBe(false);
  });

  it('semantic ON (cloud egress) DOES strip proper nouns', () => {
    const r = new Redactor({ semantic: true });
    expect(r.field('title', 'Built with React at Google')).toBe(
      'Built with <frontend-framework> at <tech-major>',
    );
  });

  it('minSeverity=high keeps an intentional contact email but kills a key', () => {
    const r = new Redactor({ minSeverity: 'high' });
    expect(r.field('description', 'reach me@example.com; key AKIAIOSFODNN7EXAMPLE')).toBe(
      'reach me@example.com; key <AWS_ACCESS_KEY>',
    );
  });

  it('produces a manifest shape that matches the wire contract', () => {
    const r = new Redactor();
    r.field('description', 'k AKIAIOSFODNN7EXAMPLE k2 AKIAIOSFODNN7EXAMPLE');
    const m = r.manifest();
    // provenance.redaction = { fields: [{ field, patterns: [{name,count,severity}], total }], total }
    expect(m.fields[0]).toMatchObject({
      field: 'description',
      total: 2,
      patterns: [{ name: 'aws-access-key', count: 2, severity: 'critical' }],
    });
    expect(m.total).toBe(2);
  });
});
