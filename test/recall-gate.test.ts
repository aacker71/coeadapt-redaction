/**
 * B8 — adversarial PII recall gate.
 *
 * Runs eval/recall-corpus.json (80 fixtures: PII hidden in the shapes real
 * repos produce — READMEs, commit messages, .env lines, JSON blobs, unicode
 * confusables, wrapped/split values, international formats) against THIS
 * library and ratchets per-category recall against eval/recall-baseline.json.
 *
 * Distinct from the B7 TS<->Python parity corpus
 * (career-box-dev/evals/redaction-parity/): parity asks "do both
 * implementations agree", this gate asks "does the library catch it at all".
 *
 * Three enforcement layers:
 *   1. expected='caught' fixtures must stay caught (finest-grain ratchet).
 *   2. expected='miss' fixtures are xfail-style documentation of current gaps:
 *      the gate asserts they STILL miss, so a pattern fix flips them visibly —
 *      promote the fixture to 'caught' and regenerate the baseline.
 *   3. Per-category recall must never drop below the committed baseline.
 *
 * Regenerate the baseline after an intentional change:
 *   npm run recall:baseline
 *
 * Do NOT delete or weaken fixtures to make this pass — fix the pattern in a
 * follow-up PR, or document the gap (expected='miss' + notes).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scrub, containsPii } from '../src/redactor-deterministic';
import { scrubSemantic } from '../src/redactor-semantic';

interface Planted {
  type: string;
  value: string;
}

interface Fixture {
  id: string;
  category: string;
  mode: 'scrub' | 'detect' | 'semantic';
  input: string;
  planted: Planted[];
  /** Extra fragments that must not survive (identifying leftovers of partial redaction). */
  mustNotSurvive?: string[];
  expected: 'caught' | 'miss';
  notes?: string;
}

interface CategoryStats {
  total: number;
  caught: number;
  recall: number;
  misses: string[];
}

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = join(HERE, '..', 'eval', 'recall-corpus.json');
const BASELINE_PATH = join(HERE, '..', 'eval', 'recall-baseline.json');

const corpus = JSON.parse(readFileSync(CORPUS_PATH, 'utf8')) as { fixtures: Fixture[] };
const fixtures = corpus.fixtures;

/** True iff the library neutralized every planted value in this fixture. */
function isCaught(f: Fixture): boolean {
  if (f.mode === 'detect') {
    return containsPii(f.input, { minSeverity: 'high' });
  }
  const out = f.mode === 'semantic' ? scrubSemantic(f.input).redacted : scrub(f.input).redacted;
  const banned = [...f.planted.map((p) => p.value), ...(f.mustNotSurvive ?? [])];
  return banned.every((s) => !out.includes(s));
}

// Measure once; every layer below reads from this.
const results = new Map<string, boolean>(fixtures.map((f) => [f.id, isCaught(f)]));

function categoryStats(): Record<string, CategoryStats> {
  const stats: Record<string, CategoryStats> = {};
  for (const f of fixtures) {
    const s = (stats[f.category] ??= { total: 0, caught: 0, recall: 0, misses: [] });
    s.total += 1;
    if (results.get(f.id)) {
      s.caught += 1;
    } else {
      s.misses.push(f.id);
    }
  }
  for (const s of Object.values(stats)) {
    s.recall = s.caught / s.total;
  }
  return stats;
}

describe('recall corpus — integrity', () => {
  it('has unique fixture ids', () => {
    const ids = fixtures.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('documents every known gap (expected=miss requires notes)', () => {
    const undocumented = fixtures.filter((f) => f.expected === 'miss' && !f.notes);
    expect(undocumented.map((f) => f.id)).toEqual([]);
  });

  it('every fixture plants at least one value', () => {
    expect(fixtures.filter((f) => f.planted.length === 0)).toEqual([]);
  });
});

describe('recall corpus — per-fixture ratchet', () => {
  for (const f of fixtures) {
    if (f.expected === 'caught') {
      it(`[${f.category}] ${f.id} — planted ${f.planted.map((p) => p.type).join('+')} is neutralized`, () => {
        expect(
          results.get(f.id),
          `RECALL REGRESSION: '${f.id}' was caught at baseline but now leaks. ` +
            `Planted: ${f.planted.map((p) => `${p.type}=${JSON.stringify(p.value)}`).join(', ')}`,
        ).toBe(true);
      });
    } else {
      it(`[${f.category}] ${f.id} — KNOWN GAP (xfail): still misses`, () => {
        expect(
          results.get(f.id),
          `Known gap '${f.id}' is now CAUGHT — the gap closed. Promote this fixture to ` +
            `expected='caught', update its notes, and regenerate the baseline ` +
            `(npm run recall:baseline). Gap notes: ${f.notes}`,
        ).toBe(false);
      });
    }
  }
});

describe('recall gate — per-category ratchet vs committed baseline', () => {
  const measured = categoryStats();

  if (process.env.RECALL_UPDATE_BASELINE === '1') {
    it('regenerates eval/recall-baseline.json from measured recall', () => {
      const overallTotal = fixtures.length;
      const overallCaught = [...results.values()].filter(Boolean).length;
      const baseline = {
        description:
          'Committed per-category recall baseline for the B8 adversarial corpus. ' +
          'The gate in test/recall-gate.test.ts fails if measured recall drops below ' +
          'these numbers. Regenerate ONLY on intentional corpus/pattern changes: ' +
          'npm run recall:baseline',
        generatedAt: new Date().toISOString().slice(0, 10),
        overall: {
          total: overallTotal,
          caught: overallCaught,
          recall: Number((overallCaught / overallTotal).toFixed(4)),
        },
        categories: Object.fromEntries(
          Object.entries(measured)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([name, s]) => [
              name,
              {
                total: s.total,
                caught: s.caught,
                recall: Number(s.recall.toFixed(4)),
                misses: s.misses,
              },
            ]),
        ),
      };
      writeFileSync(BASELINE_PATH, `${JSON.stringify(baseline, null, 2)}\n`);
      expect(true).toBe(true);
    });
    return;
  }

  const baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) as {
    overall: { total: number; caught: number; recall: number };
    categories: Record<string, { total: number; caught: number; recall: number }>;
  };

  it('covers every baseline category (none silently dropped)', () => {
    expect(Object.keys(measured).sort()).toEqual(Object.keys(baseline.categories).sort());
  });

  for (const [name, base] of Object.entries(baseline.categories)) {
    it(`${name}: recall >= baseline (${base.caught}/${base.total})`, () => {
      const s = measured[name];
      // Exact integer comparison (cross-multiplied ratios) — the stored
      // `recall` field is a rounded display value, never the gate input.
      expect(
        s.caught * base.total >= base.caught * s.total,
        `Recall in '${name}' dropped below the committed baseline ` +
          `(${s.caught}/${s.total} vs baseline ${base.caught}/${base.total}). ` +
          `Leaking fixtures: ${s.misses.join(', ') || '(none)'}`,
      ).toBe(true);
    });
  }

  it('overall recall >= baseline', () => {
    const caught = [...results.values()].filter(Boolean).length;
    expect(caught * baseline.overall.total >= baseline.overall.caught * fixtures.length).toBe(
      true,
    );
  });

  it('prints the measured recall table', () => {
    const rows = Object.entries(measured)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(
        ([name, s]) =>
          `  ${name.padEnd(24)} ${String(s.caught).padStart(2)}/${String(s.total).padEnd(3)} ${(
            s.recall * 100
          ).toFixed(0).padStart(3)}%${s.misses.length ? `  misses: ${s.misses.join(', ')}` : ''}`,
      );
    const caught = [...results.values()].filter(Boolean).length;
    // eslint-disable-next-line no-console
    console.log(
      `\nB8 adversarial recall (${caught}/${fixtures.length} = ${((caught / fixtures.length) * 100).toFixed(1)}%)\n${rows.join('\n')}\n`,
    );
    expect(true).toBe(true);
  });
});
