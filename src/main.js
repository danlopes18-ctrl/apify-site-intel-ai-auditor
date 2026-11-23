import { Actor, log } from "apify";
import { auditWebsite } from "./auditor.js";

await Actor.init();

const input = (await Actor.getInput()) || {};
const urls = Array.isArray(input.urls) ? input.urls.filter((u) => String(u || "").trim()) : [];

if (urls.length === 0) {
  log.warning("No URLs provided in input.urls — exiting cleanly.");
  await Actor.exit();
}

const options = {
  checkAiReadiness: input.checkAiReadiness !== false,
  checkSitemap: input.checkSitemap !== false,
  extractContacts: input.extractContacts !== false,
  timeoutMs: Math.min(Math.max(Number(input.timeoutMs) || 10000, 2000), 20000)
};
const maxConcurrency = Math.min(Math.max(Number(input.maxConcurrency) || 5, 1), 20);

async function safeCharge(eventName, count = 1) {
  try {
    if (typeof Actor.charge === "function") {
      await Actor.charge({ eventName, count });
    }
  } catch (err) {
    log.debug(`Charge skipped/unavailable for ${eventName}: ${err?.message || err}`);
  }
}

await safeCharge("apify-actor-start", 1);

log.info(`Auditing ${urls.length} URL(s) with concurrency=${maxConcurrency}...`);

let cursor = 0;
async function worker() {
  while (cursor < urls.length) {
    const idx = cursor++;
    const rawUrl = urls[idx];
    try {
      const result = await auditWebsite(rawUrl, options);
      await Actor.pushData(result);
      await safeCharge("domain-audited", 1);
      log.info(`[${idx + 1}/${urls.length}] ${result.domain} -> HTTP ${result.statusCode} | Sec ${result.securityGrade} | AI ${result.aiReadinessScore}/100 | Tech: ${result.techStack.join(", ")}`);
    } catch (err) {
      log.warning(`[${idx + 1}/${urls.length}] Failed ${rawUrl}: ${err?.message || err}`);
      await Actor.pushData({
        inputUrl: rawUrl,
        error: String(err?.message || err),
        auditedAt: new Date().toISOString()
      });
    }
  }
}

const workers = Array.from({ length: Math.min(maxConcurrency, urls.length) }, () => worker());
await Promise.all(workers);

log.info("Site Intel & AI-Readiness Audit complete.");
await Actor.exit();
