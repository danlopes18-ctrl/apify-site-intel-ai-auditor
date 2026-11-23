# Website Tech Stack, Security & AI-Readiness (`llms.txt`) Auditor

Fast, zero-browser website intelligence and **B2B lead enrichment** Actor — engineered for **agencies, SEO teams, sales pipelines, and autonomous AI agents (`mcp.apify.com`)**.

Runs on pure Node.js 22 without heavy headless browsers, auditing hundreds of domains in seconds at ultra-low cost.

---

## What It Extracts Per Domain

- **Tech Stack Detection (25+ signatures):** Next.js, React, Vue, Nuxt, Astro, Svelte, Tailwind CSS, WordPress, Shopify, Webflow, Framer, Cloudflare, Vercel, Netlify, AWS CloudFront, Stripe, Paddle, HubSpot, Intercom, GA4, PostHog, Segment, Sentry & more.
- **2026 AI-Readiness Score (`0–100`):**
  - Checks `/llms.txt` and `/llms-full.txt` presence + preview.
  - Parses `/robots.txt` rules specifically for `GPTBot`, `OAI-SearchBot`, `ClaudeBot`, `PerplexityBot`, and `Google-Extended`.
  - Extracts `JSON-LD` structured schema types, Open Graph, Twitter Cards, canonical tags, `<h1>`, and `/sitemap.xml` URL counts.
- **Security Headers Grade (`A+` to `F`):** Evaluates HTTPS, HSTS, Content-Security-Policy, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Public Lead Enrichment:** Deduplicated public contact emails (with noise/asset filtering) + social links (LinkedIn, X/Twitter, GitHub, YouTube, Instagram).
- **MCP-Ready `llmSummary`:** Concise one-line digest designed for Claude, Cursor, n8n, and Make agents without bloating LLM context windows.

---

## Ideal Use Cases

1. **B2B Lead Enrichment & Outbound Personalization:** Feed 500 prospect domains to instantly detect which leads run Shopify/Webflow/Next.js, lack `llms.txt`, or have grade-`D` security headers — perfect hooks for agency outreach.
2. **AI Search (GEO / AEO) Audits:** Check at scale whether client or competitor sites expose `llms.txt` or accidentally block `ClaudeBot` / `GPTBot` / `PerplexityBot` in `robots.txt`.
3. **AI Agent Tool Call (`mcp.apify.com`):** Connect directly to Claude, Cursor, or n8n to inspect any live website in under 1.5 seconds.

---

## Example Input

```json
{
  "urls": [
    "https://stripe.com",
    "https://linear.app",
    "https://danlopes18-ctrl.github.io/"
  ],
  "checkAiReadiness": true,
  "checkSitemap": true,
  "extractContacts": true,
  "maxConcurrency": 5
}
```

## Example Output Item

```json
{
  "domain": "danlopes18-ctrl.github.io",
  "statusCode": 200,
  "ttfbMs": 182,
  "techStack": ["GitHub Pages", "Gumroad"],
  "securityGrade": "B",
  "securityScore": 65,
  "aiReadinessScore": 60,
  "hasLlmsTxt": false,
  "hasSitemapXml": true,
  "sitemapUrlCount": 1,
  "jsonLdTypes": ["ItemList"],
  "llmSummary": "danlopes18-ctrl.github.io (HTTP 200, 182ms) | Tech: GitHub Pages, Gumroad | Security: B (65/100) | AI-Readiness: 60/100"
}
```

---

## Pay-Per-Event Pricing Recommendation (Apify Console)

- `apify-actor-start`: `$0.001` (optional or `$0.00`)
- `domain-audited`: `$0.005` per domain (`$5.00` per 1,000 domains enriched)
