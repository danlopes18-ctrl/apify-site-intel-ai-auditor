import dns from "node:dns/promises";
import net from "node:net";

const USER_AGENT = "SiteIntelAIAuditor/1.0 (+https://apify.com; respectful-audit-bot)";
const MAX_BODY_BYTES = 1_500_000;

export function isPrivateIp(ip) {
  if (!ip) return true;
  const clean = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  if (net.isIPv4(clean)) {
    const parts = clean.split(".").map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
    return false;
  }
  if (net.isIPv6(clean)) {
    const lower = clean.toLowerCase();
    if (lower === "::1" || lower === "::" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80") || lower.startsWith("ff")) {
      return true;
    }
    return false;
  }
  return true;
}

export function normalizeUrl(raw) {
  const trimmed = String(raw || "").trim();
  if (!trimmed) throw new Error("Empty URL");
  const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const u = new URL(withProto);
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`Unsupported protocol: ${u.protocol}`);
  }
  return u;
}

export async function assertSafeHost(hostname) {
  const lower = hostname.toLowerCase();
  if (lower === "localhost" || lower.endsWith(".local") || lower.endsWith(".internal")) {
    throw new Error(`SSRF blocked host: ${hostname}`);
  }
  if (net.isIP(lower)) {
    if (isPrivateIp(lower)) throw new Error(`SSRF blocked IP: ${lower}`);
    return;
  }
  const records = await dns.lookup(lower, { all: true });
  if (!records || records.length === 0) throw new Error(`DNS resolution failed: ${hostname}`);
  for (const rec of records) {
    if (isPrivateIp(rec.address)) {
      throw new Error(`SSRF blocked resolved private IP ${rec.address} for ${hostname}`);
    }
  }
}

async function safeFetchText(urlStr, timeoutMs = 10000, maxBytes = MAX_BODY_BYTES) {
  const u = normalizeUrl(urlStr);
  await assertSafeHost(u.hostname);
  const t0 = performance.now();
  const res = await fetch(u.toString(), {
    method: "GET",
    redirect: "follow",
    headers: {
      "User-Agent": USER_AGENT,
      "Accept": "text/html,application/xhtml+xml,text/plain,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9"
    },
    signal: AbortSignal.timeout(timeoutMs)
  });
  const ttfbMs = Math.round(performance.now() - t0);
  // Re-verify final redirected URL against SSRF
  const finalUrl = new URL(res.url || u.toString());
  if (finalUrl.hostname !== u.hostname) {
    await assertSafeHost(finalUrl.hostname);
  }
  const reader = res.body?.getReader();
  const chunks = [];
  let total = 0;
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total <= maxBytes) {
        chunks.push(value);
      } else {
        chunks.push(value.subarray(0, Math.max(0, maxBytes - (total - value.byteLength))));
        await reader.cancel().catch(() => {});
        break;
      }
    }
  }
  const body = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
  const headers = {};
  res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
  return { status: res.status, finalUrl: finalUrl.toString(), headers, body, ttfbMs, contentBytes: total };
}

function detectTechStack(html, headers) {
  const found = new Set();
  const h = headers || {};
  const server = (h["server"] || "").toLowerCase();
  const powered = (h["x-powered-by"] || "").toLowerCase();

  // Infrastructure / CDN / Hosting
  if (h["cf-ray"] || server.includes("cloudflare")) found.add("Cloudflare");
  if (h["x-vercel-id"] || server.includes("vercel")) found.add("Vercel");
  if (h["x-nf-request-id"] || server.includes("netlify")) found.add("Netlify");
  if (h["x-amz-cf-id"] || (h["via"] || "").toLowerCase().includes("cloudfront")) found.add("AWS CloudFront");
  if (h["x-served-by"]?.toLowerCase().includes("cache-") || h["fastly-restarts"]) found.add("Fastly");
  if (h["x-github-request-id"] || server.includes("github.com")) found.add("GitHub Pages");
  if (server.includes("nginx")) found.add("Nginx");
  if (server.includes("envoy")) found.add("Envoy");
  if (powered.includes("next.js") || /__NEXT_DATA__|\/_next\/static\//i.test(html)) found.add("Next.js");
  if (powered.includes("express")) found.add("Express");
  if (powered.includes("php")) found.add("PHP");

  // Frameworks, CMS, Commerce, Analytics & Payments
  const rules = [
    ["React", /data-reactroot|__REACT_DEVTOOLS|react-dom|_next\/static/i],
    ["Vue.js", /__VUE__|data-v-[0-9a-f]{6,}/i],
    ["Nuxt", /__NUXT__|\/_nuxt\//i],
    ["Astro", /astro-island|generator["'][^>]+Astro/i],
    ["Svelte", /svelte-[a-z0-9]{4,}|__sveltekit/i],
    ["Angular", /ng-version=|app-root/i],
    ["Tailwind CSS", /tailwindcss|--tw-ring-offset|class=["'][^"']*(?:flex|grid)\s+[^"']*(?:px-|py-|gap-|rounded-)/i],
    ["WordPress", /\/wp-content\/|\/wp-includes\/|generator["'][^>]+WordPress/i],
    ["Shopify", /cdn\.shopify\.com|Shopify\.theme|myshopify\.com/i],
    ["Webflow", /webflow\.com|data-wf-site=|w-webflow-badge/i],
    ["Framer", /framerusercontent\.com|generator["'][^>]+Framer/i],
    ["Wix", /static\.wixstatic\.com|wix-thunderbolt/i],
    ["Squarespace", /static1\.squarespace\.com|Squarespace/i],
    ["Ghost", /generator["'][^>]+Ghost|ghost-portal/i],
    ["Stripe", /js\.stripe\.com|checkout\.stripe\.com/i],
    ["Paddle", /cdn\.paddle\.com/i],
    ["Gumroad", /gumroad\.com/i],
    ["HubSpot", /js\.hs-scripts\.com|hs-analytics\.net/i],
    ["Intercom", /widget\.intercom\.io|intercomSettings/i],
    ["Google Analytics 4", /googletagmanager\.com\/gtag\/js|\bgtag\s*\(\s*['"]config['"]\s*,\s*['"]G-[A-Z0-9]{6,}/],
    ["Google Tag Manager", /googletagmanager\.com\/gtm\.js|['"]GTM-[A-Z0-9]{5,}['"]/],
    ["PostHog", /app\.posthog\.com|us\.i\.posthog\.com|posthog\.init/i],
    ["Plausible", /plausible\.io\/js\//i],
    ["Segment", /cdn\.segment\.com\/analytics\.js/i],
    ["Sentry", /browser\.sentry-cdn\.com|ingest\.sentry\.io/i]
  ];
  for (const [name, rx] of rules) {
    if (rx.test(html)) found.add(name);
  }
  return Array.from(found).sort();
}

function gradeSecurityHeaders(headers, finalUrl) {
  const isHttps = finalUrl.startsWith("https://");
  const checks = {
    https: isHttps,
    hsts: Boolean(headers["strict-transport-security"]),
    csp: Boolean(headers["content-security-policy"]),
    xFrameOptions: Boolean(headers["x-frame-options"] || (headers["content-security-policy"] || "").includes("frame-ancestors")),
    xContentTypeOptions: (headers["x-content-type-options"] || "").toLowerCase().includes("nosniff"),
    referrerPolicy: Boolean(headers["referrer-policy"]),
    permissionsPolicy: Boolean(headers["permissions-policy"])
  };
  const weights = { https: 25, hsts: 20, csp: 20, xFrameOptions: 10, xContentTypeOptions: 10, referrerPolicy: 8, permissionsPolicy: 7 };
  let score = 0;
  for (const [k, w] of Object.entries(weights)) {
    if (checks[k]) score += w;
  }
  let grade = "F";
  if (score >= 92) grade = "A+";
  else if (score >= 82) grade = "A";
  else if (score >= 68) grade = "B";
  else if (score >= 52) grade = "C";
  else if (score >= 35) grade = "D";
  return { securityScore: score, securityGrade: grade, securityHeaders: checks };
}

function extractSeoAndStructured(html) {
  const decode = (s) => String(s || "")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\s+/g, " ").trim();

  const title = decode((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "");
  const metaDesc = decode(
    (html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i) ||
     html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i) || [])[1] || ""
  );
  const canonical = (html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i) || [])[1] || null;
  const h1 = decode(((html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i) || [])[1] || "").replace(/<[^>]+>/g, " "));
  const hasOg = /property=["']og:title["']/i.test(html);
  const hasTwitterCard = /name=["']twitter:card["']/i.test(html);

  const jsonLdTypes = new Set();
  const ldMatches = html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi);
  for (const m of ldMatches) {
    try {
      const parsed = JSON.parse(m[1].trim());
      const items = Array.isArray(parsed) ? parsed : [parsed];
      for (const it of items) {
        if (it && it["@type"]) {
          if (Array.isArray(it["@type"])) it["@type"].forEach((t) => jsonLdTypes.add(String(t)));
          else jsonLdTypes.add(String(it["@type"]));
        }
      }
    } catch (_) {}
  }

  return {
    title,
    metaDescription: metaDesc,
    canonical,
    h1,
    hasOpenGraph: hasOg,
    hasTwitterCard,
    jsonLdTypes: Array.from(jsonLdTypes)
  };
}

function extractContactsAndSocials(html) {
  const emails = new Set();
  const junk = /\.(png|jpe?g|gif|svg|webp|ico|css|js|woff2?)$|@(example\.com|sentry\.io|wixpress\.com|w3\.org|schema\.org)|noreply@|no-reply@/i;
  for (const m of html.matchAll(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,12}/g)) {
    const email = m[0].toLowerCase();
    if (!junk.test(email) && email.length <= 80) emails.add(email);
  }

  const socials = {};
  const patterns = {
    linkedin: /https?:\/\/(?:www\.)?linkedin\.com\/(?:company|in)\/[a-zA-Z0-9._-]+/i,
    x: /https?:\/\/(?:www\.)?(?:x\.com|twitter\.com)\/(?!intent|share|home)[a-zA-Z0-9_]{2,30}/i,
    github: /https?:\/\/(?:www\.)?github\.com\/[a-zA-Z0-9-]+(?:\/[a-zA-Z0-9._-]+)?/i,
    youtube: /https?:\/\/(?:www\.)?youtube\.com\/(?:@|channel\/|c\/)[a-zA-Z0-9._-]+/i,
    instagram: /https?:\/\/(?:www\.)?instagram\.com\/[a-zA-Z0-9._-]+/i
  };
  for (const [k, rx] of Object.entries(patterns)) {
    const m = html.match(rx);
    if (m) socials[k] = m[0];
  }
  return { emails: Array.from(emails).slice(0, 15), socials };
}

function parseRobotsAiBots(robotsTxt) {
  const bots = ["GPTBot", "OAI-SearchBot", "ClaudeBot", "PerplexityBot", "Google-Extended"];
  const rules = {};
  for (const b of bots) rules[b] = "allowed";
  if (!robotsTxt) return { hasRobotsTxt: false, aiCrawlerRules: rules };

  const blocks = robotsTxt.split(/\r?\n\s*\r?\n/);
  for (const block of blocks) {
    const lines = block.split(/\r?\n/).map((l) => l.replace(/#.*$/, "").trim()).filter(Boolean);
    const agents = lines.filter((l) => /^user-agent:/i.test(l)).map((l) => l.split(":")[1].trim().toLowerCase());
    const disallowAll = lines.some((l) => /^disallow:\s*\/\s*$/i.test(l));
    const allowAll = lines.some((l) => /^allow:\s*\/\s*$/i.test(l));
    if (disallowAll && !allowAll) {
      for (const b of bots) {
        if (agents.includes(b.toLowerCase()) || agents.includes("*")) {
          rules[b] = "blocked";
        }
      }
    }
  }
  return { hasRobotsTxt: true, aiCrawlerRules: rules };
}

export async function auditWebsite(rawUrl, options = {}) {
  const {
    checkAiReadiness = true,
    checkSitemap = true,
    extractContacts = true,
    timeoutMs = 10000
  } = options;

  const u = normalizeUrl(rawUrl);
  const origin = u.origin;

  const page = await safeFetchText(u.toString(), timeoutMs, MAX_BODY_BYTES);
  const techStack = detectTechStack(page.body, page.headers);
  const security = gradeSecurityHeaders(page.headers, page.finalUrl);
  const seo = extractSeoAndStructured(page.body);
  const contacts = extractContacts ? extractContactsAndSocials(page.body) : { emails: [], socials: {} };

  let hasLlmsTxt = false;
  let llmsTxtPreview = null;
  let hasLlmsFullTxt = false;
  let robotsInfo = { hasRobotsTxt: false, aiCrawlerRules: {} };
  let sitemapInfo = { hasSitemapXml: false, sitemapUrlCount: 0 };

  const sideChecks = [];
  if (checkAiReadiness) {
    sideChecks.push(
      safeFetchText(`${origin}/llms.txt`, Math.min(timeoutMs, 6000), 50_000)
        .then((r) => {
          const ct = r.headers["content-type"] || "";
          if (r.status === 200 && !ct.includes("text/html") && r.body.trim().length > 20) {
            hasLlmsTxt = true;
            llmsTxtPreview = r.body.trim().slice(0, 280);
          }
        })
        .catch(() => {}),
      safeFetchText(`${origin}/llms-full.txt`, Math.min(timeoutMs, 5000), 20_000)
        .then((r) => {
          const ct = r.headers["content-type"] || "";
          if (r.status === 200 && !ct.includes("text/html") && r.body.trim().length > 40) {
            hasLlmsFullTxt = true;
          }
        })
        .catch(() => {}),
      safeFetchText(`${origin}/robots.txt`, Math.min(timeoutMs, 6000), 100_000)
        .then((r) => {
          if (r.status === 200 && !(r.headers["content-type"] || "").includes("text/html")) {
            robotsInfo = parseRobotsAiBots(r.body);
          }
        })
        .catch(() => {})
    );
  }
  if (checkSitemap) {
    sideChecks.push(
      safeFetchText(`${origin}/sitemap.xml`, Math.min(timeoutMs, 6000), 300_000)
        .then((r) => {
          if (r.status === 200 && /<urlset|<sitemapindex/i.test(r.body)) {
            const count = (r.body.match(/<loc>/gi) || []).length;
            sitemapInfo = { hasSitemapXml: true, sitemapUrlCount: count };
          }
        })
        .catch(() => {})
    );
  }
  await Promise.all(sideChecks);

  // Compute AI-Readiness Score (0-100)
  let aiScore = 0;
  if (hasLlmsTxt) aiScore += 30;
  if (hasLlmsFullTxt) aiScore += 10;
  if (seo.jsonLdTypes.length > 0) aiScore += 20;
  if (seo.metaDescription && seo.title && seo.h1) aiScore += 15;
  if (sitemapInfo.hasSitemapXml) aiScore += 10;
  const allowedBots = Object.values(robotsInfo.aiCrawlerRules).filter((v) => v === "allowed").length;
  if (allowedBots >= 4) aiScore += 15;
  else if (allowedBots >= 2) aiScore += 8;

  const llmSummary = [
    `${u.hostname} (HTTP ${page.status}, ${page.ttfbMs}ms)`,
    `Tech: ${techStack.length ? techStack.join(", ") : "None detected"}`,
    `Security: ${security.securityGrade} (${security.securityScore}/100)`,
    `AI-Readiness: ${aiScore}/100 (llms.txt=${hasLlmsTxt}, JSON-LD=${seo.jsonLdTypes.join(",") || "none"})`,
    contacts.emails.length ? `Emails: ${contacts.emails.slice(0, 3).join(", ")}` : null
  ].filter(Boolean).join(" | ");

  return {
    inputUrl: rawUrl,
    finalUrl: page.finalUrl,
    domain: u.hostname,
    statusCode: page.status,
    ttfbMs: page.ttfbMs,
    contentBytes: page.contentBytes,
    title: seo.title,
    metaDescription: seo.metaDescription,
    h1: seo.h1,
    canonical: seo.canonical,
    hasOpenGraph: seo.hasOpenGraph,
    hasTwitterCard: seo.hasTwitterCard,
    jsonLdTypes: seo.jsonLdTypes,
    techStack,
    securityScore: security.securityScore,
    securityGrade: security.securityGrade,
    securityHeaders: security.securityHeaders,
    aiReadinessScore: aiScore,
    hasLlmsTxt,
    hasLlmsFullTxt,
    llmsTxtPreview,
    hasRobotsTxt: robotsInfo.hasRobotsTxt,
    aiCrawlerRules: robotsInfo.aiCrawlerRules,
    hasSitemapXml: sitemapInfo.hasSitemapXml,
    sitemapUrlCount: sitemapInfo.sitemapUrlCount,
    emails: contacts.emails,
    socials: contacts.socials,
    llmSummary,
    auditedAt: new Date().toISOString()
  };
}
