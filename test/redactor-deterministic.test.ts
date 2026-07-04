import { describe, it, expect } from 'vitest';
import { scrub, containsPii } from '../src/redactor-deterministic';

describe('scrub — critical credentials (never reach an egress path)', () => {
  it('redacts an AWS access key', () => {
    const { redacted, replacements } = scrub('key is AKIAIOSFODNN7EXAMPLE done');
    expect(redacted).toBe('key is <AWS_ACCESS_KEY> done');
    expect(replacements).toHaveLength(1);
    expect(replacements[0].pattern).toBe('aws-access-key');
    expect(replacements[0].severity).toBe('critical');
  });

  it('redacts an Anthropic key before the generic fallback', () => {
    const { redacted, replacements } = scrub('sk-ant-api03-abc123def456ghi789');
    expect(redacted).toBe('<ANTHROPIC_KEY>');
    expect(replacements[0].pattern).toBe('anthropic-api-key');
  });

  it('redacts a PEM private key block', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----';
    expect(scrub(`leaked: ${pem}`).redacted).toBe('leaked: <PEM_KEY>');
  });

  it('redacts GitHub tokens and JWTs', () => {
    expect(scrub('ghp_' + 'a'.repeat(36)).redacted).toBe('<GITHUB_TOKEN>');
    // Real JWT: three base64url segments, each >= 8 chars after the eyJ prefix.
    const jwt = 'eyJ' + 'a'.repeat(10) + '.' + 'b'.repeat(10) + '.' + 'c'.repeat(10);
    expect(scrub(jwt).redacted).toBe('<JWT>');
  });

  it('over-redacts a too-short JWT-like token as a hostname (safe fail)', () => {
    // Documents the real behavior the test above originally tripped on: a token
    // too short to be a valid JWT still gets redacted (FQDN catches it) — never
    // passed through. Over-redaction is the safe direction.
    expect(scrub('eyJhbGciOi.eyJzdWIiOi.SflKxwRJ').redacted).toBe('<HOSTNAME>');
  });
});

describe('scrub — high severity (gov / financial)', () => {
  it('redacts SSNs and card-like digit runs', () => {
    expect(scrub('ssn 123-45-6789').redacted).toBe('ssn <SSN>');
    expect(scrub('card 4111111111111111').redacted).toBe('card <CC>');
  });

  it('redacts cards written with spaces or dashes', () => {
    expect(scrub('card 4111 1111 1111 1111 on file').redacted).toBe('card <CC> on file');
    expect(scrub('card 4111-1111-1111-1111 on file').redacted).toBe('card <CC> on file');
  });

  it('does not treat a 10-digit phone-length run as a card', () => {
    expect(scrub('ref 4155550199', { minSeverity: 'high' }).redacted).toBe('ref 4155550199');
  });

  it('redacts a full DOB in slash or dash form', () => {
    expect(scrub('born 04/12/1988 in Boston').redacted).toBe('born <DOB> in Boston');
    expect(scrub('DOB: 4-12-1988').redacted).toBe('DOB: <DOB>');
  });

  it('leaves ISO dates alone (year-first)', () => {
    expect(scrub('deployed 2026-07-04', { minSeverity: 'high' }).redacted).toBe(
      'deployed 2026-07-04',
    );
  });

  it('redacts keyword-anchored passport numbers', () => {
    expect(scrub('my passport no: X1234567 expires soon').redacted).toBe('my <PASSPORT> expires soon');
    expect(scrub('Passport number AB123456').redacted).toBe('<PASSPORT>');
  });

  it('redacts keyword-anchored routing / account numbers', () => {
    expect(scrub('routing number 021000021').redacted).toBe('<ACCOUNT_NUMBER>');
    expect(scrub('account #: 123456789012').redacted).toBe('<ACCOUNT_NUMBER>');
  });

  it('prefers the specific account placeholder over the card fallback', () => {
    expect(scrub('account number 4111111111111111').redacted).toBe('<ACCOUNT_NUMBER>');
  });

  it('detects a separator-less 9-digit SSN but never rewrites it (detectOnly)', () => {
    expect(containsPii('ssn is 123456789', { minSeverity: 'high' })).toBe(true);
    // scrub must NOT mask bare 9-digit runs — too false-positive-prone
    // (build numbers, order ids) to rewrite egress text with.
    expect(scrub('build 123456789 shipped').redacted).toBe('build 123456789 shipped');
  });

  it('does not flag innocuous engineering numbers at high severity', () => {
    expect(containsPii('we shipped 42 PRs and reduced p99 by 18ms', { minSeverity: 'high' })).toBe(
      false,
    );
  });
});

describe('scrub — medium / low (contact + network)', () => {
  it('redacts emails, URLs, IPs, phones', () => {
    expect(scrub('me@example.com').redacted).toBe('<EMAIL>');
    expect(scrub('see https://secret.internal/x').redacted).toBe('see <URL>');
    expect(scrub('host 10.0.0.1').redacted).toBe('host <IP>');
    expect(scrub('call 415-555-0199').redacted).toBe('call <PHONE>');
  });

  it('redacts home paths that leak a username', () => {
    expect(scrub('/Users/alexsmith/secret.txt').redacted).toBe('<HOME_PATH>');
  });
});

describe('scrub — severity thresholding (minSeverity)', () => {
  const mixed = 'key AKIAIOSFODNN7EXAMPLE email me@example.com';

  it('default (low) scrubs everything', () => {
    expect(scrub(mixed).redacted).toBe('key <AWS_ACCESS_KEY> email <EMAIL>');
  });

  it('minSeverity=high keeps emails/URLs but still kills credentials', () => {
    const { redacted } = scrub(mixed, { minSeverity: 'high' });
    expect(redacted).toBe('key <AWS_ACCESS_KEY> email me@example.com');
  });

  it('minSeverity=critical keeps SSNs too', () => {
    expect(scrub('ssn 123-45-6789', { minSeverity: 'critical' }).redacted).toBe('ssn 123-45-6789');
  });
});

describe('scrub — invariants', () => {
  it('never leaks the original secret into the output', () => {
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    expect(scrub(`x ${secret} y`).redacted).not.toContain(secret);
  });

  it('handles empty / nullish input', () => {
    expect(scrub('').redacted).toBe('');
    expect(scrub(null).redacted).toBe('');
    expect(scrub(undefined).replacements).toHaveLength(0);
  });

  it('is stable across repeated calls (lastIndex reset)', () => {
    const a = scrub('me@example.com');
    const b = scrub('me@example.com');
    expect(a.redacted).toBe(b.redacted);
  });
});

describe('containsPii', () => {
  it('detects at threshold and respects minSeverity', () => {
    expect(containsPii('me@example.com')).toBe(true);
    expect(containsPii('me@example.com', { minSeverity: 'critical' })).toBe(false);
    expect(containsPii('AKIAIOSFODNN7EXAMPLE', { minSeverity: 'critical' })).toBe(true);
  });
});
