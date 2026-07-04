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

export const SEED_TAXONOMY: TaxonomySeed = {
  version: 1,
  categories: {
    companies: {
      Stripe: 'fintech-infra',
      Square: 'fintech-infra',
      Plaid: 'fintech-infra',
      'Goldman Sachs': 'finance-bank',
      JPMorgan: 'finance-bank',
      Google: 'tech-major',
      Meta: 'tech-major',
      Microsoft: 'tech-major',
      Amazon: 'tech-major',
      Apple: 'tech-major',
      Anthropic: 'ai-major',
      OpenAI: 'ai-major',
      Salesforce: 'enterprise-saas',
      Notion: 'productivity-saas',
      Slack: 'productivity-saas',
    },
    tools: {
      GitHub: 'dev-tool',
      GitLab: 'dev-tool',
      Jira: 'project-management',
      Linear: 'project-management',
      Figma: 'design-tool',
      Sketch: 'design-tool',
      'VS Code': 'ide',
      IntelliJ: 'ide',
      Docker: 'devops-tool',
      Kubernetes: 'devops-tool',
      Terraform: 'devops-tool',
      AWS: 'cloud-provider',
      GCP: 'cloud-provider',
      Azure: 'cloud-provider',
      Vercel: 'cloud-provider',
    },
    skills: {
      React: 'frontend-framework',
      Vue: 'frontend-framework',
      Angular: 'frontend-framework',
      'Next.js': 'frontend-framework',
      'Node.js': 'runtime',
      Python: 'language',
      TypeScript: 'language',
      JavaScript: 'language',
      Rust: 'language',
      Go: 'language',
      PostgreSQL: 'database',
      MongoDB: 'database',
      Redis: 'cache-store',
      GraphQL: 'api-style',
      REST: 'api-style',
    },
    locations: {
      'San Francisco': 'us-region-west',
      'New York': 'us-region-east',
      London: 'eu-region-uk',
      Berlin: 'eu-region-de',
      Tokyo: 'asia-region-jp',
    },
  },
};
