/**
 * Field-level redaction firewall.
 *
 * `Redactor` scrubs a set of named free-text fields and accumulates a per-field
 * manifest — pattern names + counts ONLY, never the matched secret. This is the
 * exact shape both the producer's submission `provenance.redaction` and the
 * consumer's authoritative re-scrub record, so a user can audit
 * "description: 2 redactions (aws-access-key, email)" without the secret ever
 * being persisted.
 *
 * Usage (consumer chokepoint — all severities, semantic OFF):
 *
 *   const r = new Redactor();
 *   body.name        = r.field("name", body.name);
 *   body.description = r.field("description", body.description);
 *   body.accomplishments = body.accomplishments.map((a, i) => ({
 *     ...a,
 *     title:  r.field(`accomplishments[${i}].title`,  a.title),
 *     detail: r.field(`accomplishments[${i}].detail`, a.detail),
 *   }));
 *   const manifest = r.manifest(); // { fields, total }
 */

import { scrub, type ScrubOptions } from './redactor-deterministic.js';
import { scrubSemantic } from './redactor-semantic.js';

export interface FieldRedaction {
  field: string;
  patterns: Array<{ name: string; count: number; severity: string }>;
  total: number;
}

export interface RedactionManifest {
  fields: FieldRedaction[];
  total: number;
}

export interface RedactorOptions extends ScrubOptions {
  /**
   * Also run the semantic taxonomy pass after the deterministic scrub. Default
   * false. Enable ONLY for cloud-LLM egress (never for the public portfolio —
   * it replaces real entities with class placeholders).
   */
  semantic?: boolean;
}

/**
 * Stateful accumulator: call `field()` per free-text field, then `manifest()`.
 * One instance per submission/record.
 */
export class Redactor {
  private readonly fields: FieldRedaction[] = [];

  constructor(private readonly opts: RedactorOptions = {}) {}

  /** Scrub one named field, record its manifest entry, return the clean text. */
  field(name: string, value: string | null | undefined): string {
    const { redacted, replacements } = scrub(value ?? '', { minSeverity: this.opts.minSeverity });

    if (replacements.length > 0) {
      const byPattern = new Map<string, { count: number; severity: string }>();
      for (const r of replacements) {
        const prev = byPattern.get(r.pattern);
        if (prev) prev.count += 1;
        else byPattern.set(r.pattern, { count: 1, severity: r.severity });
      }
      this.fields.push({
        field: name,
        patterns: [...byPattern.entries()].map(([name, v]) => ({
          name,
          count: v.count,
          severity: v.severity,
        })),
        total: replacements.length,
      });
    }

    return this.opts.semantic ? scrubSemantic(redacted).redacted : redacted;
  }

  /** True once any field has been redacted. */
  get touched(): boolean {
    return this.fields.length > 0;
  }

  /** The accumulated manifest (matches the wire `provenance.redaction` shape). */
  manifest(): RedactionManifest {
    return {
      fields: this.fields,
      total: this.fields.reduce((n, f) => n + f.total, 0),
    };
  }
}
