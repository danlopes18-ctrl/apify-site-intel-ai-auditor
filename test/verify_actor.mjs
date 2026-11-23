import assert from "node:assert/strict";
import { auditWebsite, isPrivateIp } from "../src/auditor.js";

console.log("=== QA: Site Intel & AI-Readiness Auditor ===");

// 1. SSRF Shield unit assertions
assert.equal(isPrivateIp("127.0.0.1"), true, "must block loopback");
assert.equal(isPrivateIp("169.254.169.254"), true, "must block cloud metadata");
assert.equal(isPrivateIp("10.0.0.5"), true, "must block RFC1918 10/8");
assert.equal(isPrivateIp("192.168.1.1"), true, "must block RFC1918 192.168/16");
assert.equal(isPrivateIp("::1"), true, "must block IPv6 loopback");
assert.equal(isPrivateIp("1.1.1.1"), false, "must allow public IP");

let ssrfBlocked = false;
try {
  await auditWebsite("http://169.254.169.254/latest/meta-data/");
} catch (e) {
  ssrfBlocked = String(e.message).includes("SSRF blocked");
}
assert.equal(ssrfBlocked, true, "must reject cloud metadata URL");
console.log("PASS 1/3: DNS-verified SSRF Shield verified");

// 2. Live audit against our own live storefront
const res1 = await auditWebsite("https://danlopes18-ctrl.github.io/");
assert.equal(res1.statusCode, 200, "storefront HTTP 200");
assert.ok(res1.title.includes("Daniel Lopes"), "title parsed");
assert.ok(res1.techStack.includes("GitHub Pages"), "detected GitHub Pages");
assert.ok(res1.jsonLdTypes.includes("ItemList"), "detected JSON-LD ItemList");
assert.equal(res1.hasSitemapXml, true, "detected sitemap.xml");
assert.equal(res1.hasRobotsTxt, true, "detected robots.txt");
assert.ok(res1.aiReadinessScore >= 40, "AI readiness scored");
assert.ok(res1.llmSummary.includes("danlopes18-ctrl.github.io"), "llmSummary generated");
console.log("PASS 2/3: Live Storefront Audit ->", res1.llmSummary);

// 3. Live audit against stripe.com (major production SaaS site)
const res2 = await auditWebsite("https://stripe.com");
assert.equal(res2.statusCode, 200, "stripe HTTP 200");
assert.ok(res2.securityScore >= 50, "security headers graded");
assert.ok(res2.ttfbMs > 0, "TTFB measured");
console.log("PASS 3/3: Live SaaS Audit ->", res2.llmSummary);

console.log("\nALL 3/3 LIVE QA SUITES PASSED!");
