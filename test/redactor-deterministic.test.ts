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
