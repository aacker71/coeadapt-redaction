# Integrating `@coeadapt/redaction` into the two repos

Apply this once both repos are at a clean base. It is written to compose with the
in-flight work and **not** fight it:

- **Coeadapt2 `feat/portfolio-public-safety-gate`** adds *projection* (which fields
  reach the public page). This adds *content redaction* (whether those fields
  carry secrets). They stack — apply this after that branch lands.
- **career-box-dev `submission-contract.ts`** dedups the *contract types*. This
  touches the *scrub logic*, not the types, so there is no overlap except the
  shared file `portfolio-submitter.ts` (coordinate that one import swap).

The package's `FieldRedaction` shape is identical to `submission-contract.ts`'s
`provenance.redaction`, so the manifests are wire-compatible.

---

## 0. Publish + install (D4 — GitHub Packages)

```bash
# In coeadapt-redaction/ (this repo): make it a real repo and publish.
git init && git add -A && git commit -m "feat: @coeadapt/redaction v1.0.0"
# Create the GitHub repo under the org that OWNS the @coeadapt npm scope
# (confirm: org `coeadapt` vs user `alexander-acker` — GitHub Packages maps the
# npm scope to the repo owner). Push, then:
git tag v1.0.0 && git push --tags   # .github/workflows/publish.yml publishes it
```

Both consuming repos need an `.npmrc` (committed) + a `GITHUB_TOKEN` with
`read:packages` available at install time — locally AND in the Coeadapt2
AppRunner Docker build:

```
@coeadapt:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

> **Local dev before the first publish:** in `coeadapt-redaction/` run
> `npm run build && npm link`, then in each consuming repo `npm link @coeadapt/redaction`.
> This resolves the import without the registry so you can run both suites.
> The committed `package.json` still references `"@coeadapt/redaction": "^1.0.0"`.

---

## 1. Coeadapt2 — the consumer chokepoint (closes Holes 2 + 3)

`package.json`: add `"@coeadapt/redaction": "^1.0.0"`.

`server/routes/career-box.ts` — insert immediately after `const body = parsed.data;`
(currently line ~664):

```ts
import { Redactor } from "@coeadapt/redaction";

// ...inside the POST handler, right after `const body = parsed.data;`

// Authoritative server-side redaction chokepoint. EVERY producer funnels through
// here: the desktop (Stage-1 already), the draft-sync sweeper (bypasses it), and
// the claude-code plugin (no redactor at all). Re-scrub free-text CONTENT so no
// secret is ever persisted or rendered public, regardless of who sent it.
// All severities; semantic OFF — running the taxonomy pass here would replace the
// user's real skills/employers and gut the portfolio.
const redactor = new Redactor();
body.name = redactor.field("name", body.name);
body.tagline = redactor.field("tagline", body.tagline);
body.description = redactor.field("description", body.description);
body.accomplishments = body.accomplishments.map((a, i) => ({
  ...a,
  title: redactor.field(`accomplishments[${i}].title`, a.title),
  detail: redactor.field(`accomplishments[${i}].detail`, a.detail),
}));
body.media.screenshots = body.media.screenshots.map((s, i) => ({
  ...s,
  caption: s.caption
    ? redactor.field(`media.screenshots[${i}].caption`, s.caption)
    : s.caption,
}));

// The SERVER is the source of truth for the manifest now — a producer can
// under-report what it scrubbed; the server cannot. Record what WE actually did.
const serverRedaction = redactor.manifest();
```

Then replace the producer-trusted manifest reads with the server-authoritative one:

- audit row `actionData.redactionTotal: prov?.redaction?.total ?? 0` → `serverRedaction.total`
- item metadata `provenance` merge: set `provenance.redaction = serverRedaction`
  (keep the producer's `drafting`/`submissionId`/`metricsTier`; override `redaction`)

> Note: `media.screenshots[].caption` is scrubbed here even though the producer
> never scrubbed it — a genuine gap this closes on both sides.

### Contract test — the smoking gun (the bypass that is open today)

`server/tests/routes/careerBoxPortfolioProject.test.ts` — add:

```ts
it("scrubs secrets from a claude-code-plugin submission before it is stored/public", async () => {
  const res = await postProject({
    ...validSubmission(),
    source: "claude-code-plugin",     // the no-redactor producer
    isPublic: true,
    description: "Shipped billing. AWS key AKIAIOSFODNN7EXAMPLE, ssn 123-45-6789.",
  });
  expect(res.status).toBe(201);
  // Persisted + rendered text carries no secret.
  const ev = await loadEvidenceForProject(res.body.projectId);
  expect(ev.some((e) => /AKIAIOSFODNN7EXAMPLE|123-45-6789/.test(e.rawContent ?? ""))).toBe(false);
  // Manifest recorded what fired, never the secret.
  // (assert serverRedaction surfaced wherever you persist it)
});
```

---

## 2. career-box-dev — the producer (closes Hole 1, removes the duplicate copies)

`package.json`: add `"@coeadapt/redaction": "^1.0.0"`.

### 2a. Stop raw browser titles reaching Anthropic (Hole 1)

`src/main/evidence/activity-evidence-engine.ts` → `generateForGroup`, before building
`userPrompt` (currently ~line 108):

```ts
import { scrub, scrubSemantic } from "@coeadapt/redaction";

// Deterministic + semantic scrub BEFORE anything leaves for api.anthropic.com.
// This is the egress point the redactor-semantic header was written for.
const safeTitle = (t: string) => scrubSemantic(scrub(t).redacted).redacted;
const titlesSnippet = group.titles.slice(0, 5).map(safeTitle).join("; ");
const topDomains = [...group.domains]
  .sort((a, b) => b.duration - a.duration)
  .slice(0, 5)
  .map((d) => `${safeTitle(d.hostname)} (${Math.round(d.duration / 60_000)}min)`)
  .join(", ");
```

### 2b. Delete the local copies, repoint all importers to the package

Delete:
- `src/main/privacy/redactor-deterministic.ts`
- `src/main/privacy/redactor-semantic.ts`
- `src/main/privacy/pii-patterns.ts`
- `src/main/privacy/taxonomy/` (+ `taxonomy.schema.json`)

Repoint every importer to `@coeadapt/redaction`:
- `src/main/portfolio/portfolio-submitter.ts` — `scrubAtIngest` → `scrub`
  (**coordinate**: this file is also edited by the `submission-contract.ts` work)
- `src/navi/brain/sensitivity.ts` — imports `PII_PATTERNS` / `SENSITIVITY_HINTS`
- the redactor eval harness under `evals/redactor-impact-on-navi/`

> Grep `from '.*privacy/(redactor|pii-patterns)'` to find every site before deleting.

### 2c. Keep the Python copy honest (parity)

`local_runtime/redaction.py` can't import an npm package, so it stays separate.
Add a parity test asserting its pattern names + placeholders match
`PII_PATTERNS` from `@coeadapt/redaction` (the two already claim parity by comment
— make it a test).

---

## Verify

- `coeadapt-redaction`: `npm test` (27 green) + `npm run build`.
- Coeadapt2: the new contract test + existing `careerBoxPortfolioProject` /
  `publicPortfolioSanitize` suites.
- career-box-dev: redactor unit tests (now pointing at the package) + the new
  Python parity test.
- Manual seam: publish a project whose description contains a fake key → confirm
  `/p/:slug` shows `<AWS_ACCESS_KEY>`, not the key.
