# @coeadapt/redaction

The shared PII redaction firewall for the Coeadapt portfolio pipeline. One source
of truth for **every** egress path that can leak a user's raw text:

| Egress | Repo | What runs |
|--------|------|-----------|
| Repo → public portfolio (`/p/:slug`) | Coeadapt2 (consumer) | `Redactor` — deterministic, **all severities**, semantic OFF |
| Browser activity → Anthropic (frontier evidence) | career-box-dev (producer) | `scrub` + `scrubSemantic` — deterministic + taxonomy |

> The Python copy in `career-box-dev/local_runtime/redaction.py` cannot consume an
> npm package. It stays a separate implementation, kept in lockstep by the
> cross-repo parity test. This package is the single source of truth for **all
> TypeScript** consumers.

## Why semantic is opt-in (and OFF for the portfolio)

The deterministic stage strips PII (keys, emails, URLs, SSNs, paths, IPs) but
leaves proper nouns intact. The semantic stage replaces named entities
(`Google` → `<tech-major>`, `React` → `<frontend-framework>`) from a curated
taxonomy. That is correct when protecting raw activity from a cloud LLM, but it
would **gut a public portfolio** ("worked at `<tech-major>` using
`<frontend-framework>`"). So semantic only runs where hiding the specific entity
is the goal — never on the portfolio.

## API

```ts
import { Redactor, scrub, scrubSemantic, PII_PATTERNS } from "@coeadapt/redaction";

// Field-by-field scrub with a per-field manifest (the wire-contract shape).
const r = new Redactor();                 // all severities, semantic off
const name        = r.field("name", input.name);
const description = r.field("description", input.description);
const manifest    = r.manifest();         // { fields: FieldRedaction[], total }

// One-shot deterministic scrub.
const { redacted, replacements } = scrub(text);                  // all severities
const { redacted } = scrub(text, { minSeverity: "high" });        // critical+high only

// Semantic taxonomy pass (cloud-egress only).
const { redacted: safe } = scrubSemantic(scrub(text).redacted);
```

## Consuming repos

Both repos need an `.npmrc` mapping the scope to GitHub Packages and a
`GITHUB_TOKEN` with `read:packages` available at install time (local + the
Coeadapt2 Docker/AppRunner build):

```
@coeadapt:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```
