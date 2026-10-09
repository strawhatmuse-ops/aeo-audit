#!/usr/bin/env node
/**
 * aeo-audit — check whether AI answer engines can read and cite your pages.
 *
 * Zero dependencies. Plain Node.js (>=18). Same 6 checks and scoring as the
 * Digital Dabbi web auditor — ported faithfully, not reimplemented.
 *
 * Usage: aeo-audit <url> [--json] [--no-color]
 */

import { lookup } from "node:dns/promises";

const VERSION = "0.1.0";
const PAGE_TIMEOUT_MS = 15_000;
const PAGE_MAX_BYTES = 2 * 1024 * 1024;
const LLMS_TIMEOUT_MS = 6_000;
const LLMS_MAX_BYTES = 100 * 1024;
const MAX_REDIRECTS = 5;
const UA = `DigitalDabbi-Audit-CLI/${VERSION} (+https://github.com/strawhatmuse-ops/aeo-audit)`;

/* ------------------------------------------------------------------ */
/* CLI plumbing                                                        */
/* ------------------------------------------------------------------ */

const rawArgs = process.argv.slice(2);
let noColor = false;
let asJson = false;
let urlArg = null;

for (const a of rawArgs) {
  if (a === "--json") asJson = true;
  else if (a === "--no-color") noColor = true;
  else if (a === "--help" || a === "-h") {
    printHelp();
    process.exit(0);
  } else if (a === "--version" || a === "-v") {
    console.log(VERSION);
    process.exit(0);
  } else if (a.startsWith("-")) {
    fail(`Unknown flag: ${a}\nRun \`aeo-audit --help\`.`);
  } else if (urlArg === null) {
    urlArg = a;
  } else {
    fail("Too many arguments. Usage: aeo-audit <url>");
  }
}

if (urlArg === null) {
  printHelp();
  process.exit(1);
}

const useColor = !noColor && process.stdout.isTTY === true;
const GREEN = useColor ? "\x1b[32m" : "";
const RED = useColor ? "\x1b[31m" : "";
const BOLD = useColor ? "\x1b[1m" : "";
const DIM = useColor ? "\x1b[2m" : "";
const RESET = useColor ? "\x1b[0m" : "";

function printHelp() {
  console.log(
    `aeo-audit v${VERSION} — do AI answers mention your brand?

Usage:
  aeo-audit <url> [--json] [--no-color]

Checks (0–100):
  llms.txt, schema.org, question headings, answer blocks,
  entity signals, performance.

Flags:
  --json       machine-readable output
  --no-color   plain output, no ANSI codes
  --help       this text
  --version    print version

Part of the @digitaldabbi toolchain. https://github.com/strawhatmuse-ops/aeo-audit`
  );
}

function fail(msg) {
  console.error(`${useColor ? RED : ""}error:${RESET} ${msg}`);
  process.exit(1);
}

/* ------------------------------------------------------------------ */
/* SSRF guard: block private / loopback / link-local / multicast hosts */
/* (ported from the web auditor — same rules)                           */
/* ------------------------------------------------------------------ */

function isBlockedIPv4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p))) return false;
  const [a, b] = parts.map(Number);
  if (a > 255 || b > 255) return false;
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a >= 224 && a <= 239) ||
    a === 0
  );
}

function isBlockedIP(ip) {
  const low = ip.toLowerCase().trim();
  const mapped = low.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return isBlockedIPv4(mapped[1]);
  const compat = low.match(/^::(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (compat) return isBlockedIPv4(compat[1]);
  if (low === "::" || low === "::1") return true;
  if (low.includes(":")) {
    const firstHex = low.split(":")[0];
    const first = firstHex === "" ? 0 : parseInt(firstHex, 16);
    if (Number.isNaN(first)) return true;
    if (first >= 0xfe80 && first <= 0xfebf) return true;
    if (first >= 0xfc00 && first <= 0xfdff) return true;
    if (first >= 0xff00) return true;
    return false;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(low)) return isBlockedIPv4(low);
  return true; // fail closed
}

async function assertPublicHost(hostname) {
  let addrs;
  try {
    addrs = await lookup(hostname, { all: true });
  } catch {
    throw new Error("That hostname could not be resolved.");
  }
  if (addrs.length === 0) throw new Error("That hostname could not be resolved.");
  if (addrs.some((a) => isBlockedIP(a.address))) {
    throw new Error("That address is not allowed (private / loopback / link-local).");
  }
}

/* ------------------------------------------------------------------ */
/* Capped fetch with manual redirect handling + timeout                */
/* ------------------------------------------------------------------ */

class FetchFailed extends Error {}

async function readCapped(body, maxBytes) {
  if (!body) return "";
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new FetchFailed("Response too large.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(merged);
}

async function fetchCapped(startUrl, timeoutMs, maxBytes) {
  let current = startUrl;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let parsed;
    try {
      parsed = new URL(current);
    } catch {
      throw new FetchFailed("Invalid redirect target.");
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new FetchFailed("Redirect left http(s).");
    }
    // SSRF guard on every hop — defeats DNS-rebinding / redirect tricks.
    try {
      await assertPublicHost(parsed.hostname);
    } catch (e) {
      throw new FetchFailed(e instanceof Error ? e.message : "That address is not allowed.");
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(current, {
        signal: ctrl.signal,
        redirect: "manual",
        headers: {
          "User-Agent": UA,
          Accept: "text/html,application/xhtml+xml,text/plain,*/*;q=0.8",
        },
      });
    } catch (e) {
      clearTimeout(timer);
      throw new FetchFailed(
        e instanceof Error && e.name === "AbortError" ? "Request timed out." : "Network error."
      );
    } finally {
      clearTimeout(timer);
    }

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      await res.body?.cancel().catch(() => undefined);
      if (!loc) throw new FetchFailed("Redirect without a location.");
      try {
        current = new URL(loc, current).toString();
      } catch {
        throw new FetchFailed("Invalid redirect target.");
      }
      continue;
    }

    const len = Number(res.headers.get("content-length"));
    if (Number.isFinite(len) && len > maxBytes) {
      await res.body?.cancel().catch(() => undefined);
      throw new FetchFailed("Response too large.");
    }
    const body = await readCapped(res.body, maxBytes);
    return { status: res.status, body, finalUrl: current };
  }
  throw new FetchFailed("Too many redirects.");
}

/* ------------------------------------------------------------------ */
/* Regex-only HTML parsing                                             */
/* ------------------------------------------------------------------ */

function decodeEntities(s) {
  return s
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'");
}

function cleanText(raw) {
  return decodeEntities(raw.replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
}

function stripScriptsAndStyles(html) {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, " ");
}

function tagContents(html, tag) {
  const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}\\s*>`, "gi");
  const out = [];
  let m;
  while ((m = re.exec(html)) !== null) out.push(m[1]);
  return out;
}

function getTitle(html) {
  const m = html.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i);
  return m ? cleanText(m[1]) : "";
}

function hasViewportMeta(html) {
  return /<meta\b[^>]*\bname\s*=\s*["']?viewport["']?[^>]*>/i.test(html);
}

function getJsonLdBlocks(html) {
  const re =
    /<script\b[^>]*\btype\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script\s*>/gi;
  const out = [];
  let m;
  while ((m = re.exec(html)) !== null) out.push(m[1]);
  return out;
}

function walkSchema(node, types, orgs) {
  if (Array.isArray(node)) {
    for (const n of node) walkSchema(n, types, orgs);
    return;
  }
  if (!node || typeof node !== "object") return;
  const rec = node;
  const t = rec["@type"];
  const typeList = Array.isArray(t) ? t : typeof t === "string" ? [t] : [];
  for (const ty of typeList) if (typeof ty === "string") types.add(ty);
  if (typeList.some((ty) => ty === "Organization" || ty === "LocalBusiness")) {
    if (!orgs.includes(rec)) orgs.push(rec);
  }
  for (const key of Object.keys(rec)) {
    if (key === "@type") continue;
    walkSchema(rec[key], types, orgs);
  }
}

const QUESTION_WORDS = new Set([
  "who", "what", "when", "where", "why", "how",
  "is", "are", "can", "does", "did", "will", "should",
]);

function isQuestionHeading(text) {
  const t = text.trim();
  if (!t) return false;
  if (t.endsWith("?")) return true;
  const first = t.split(/\s+/)[0].toLowerCase().replace(/[^a-z]/g, "");
  return QUESTION_WORDS.has(first);
}

function wordCount(s) {
  const w = s.trim().split(/\s+/).filter(Boolean);
  return w.length === 1 && w[0] === "" ? 0 : w.length;
}

function verdictFor(score) {
  if (score >= 80) return "CITED AND VISIBLE.";
  if (score >= 50) return "HALFWAY INTO THE ANSWER.";
  return "INVISIBLE IN AI ANSWERS.";
}

/* ------------------------------------------------------------------ */
/* Audit                                                               */
/* ------------------------------------------------------------------ */

async function audit(targetUrl) {
  let parsed;
  const withProto = /^[a-z][a-z0-9+.-]*:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`;
  try {
    parsed = new URL(withProto);
  } catch {
    throw new Error("Please enter a valid http(s) URL.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Please enter a valid http(s) URL.");
  }

  try {
    await assertPublicHost(parsed.hostname);
  } catch (e) {
    throw new Error(e instanceof Error ? e.message : "That address is not allowed.");
  }

  const started = Date.now();
  let page;
  try {
    page = await fetchCapped(parsed.toString(), PAGE_TIMEOUT_MS, PAGE_MAX_BYTES);
  } catch (e) {
    throw new Error(e instanceof FetchFailed ? e.message : "Network error.");
  }
  const durationMs = Date.now() - started;

  if (page.status >= 400) {
    throw new Error(`Server returned status ${page.status}.`);
  }

  const html = page.body;
  const clean = stripScriptsAndStyles(html);

  /* --- llms.txt (20) --- */
  let llmsPass = false;
  let llmsDetail = "No llms.txt found at the site root.";
  try {
    const origin = new URL(page.finalUrl).origin;
    const llms = await fetchCapped(`${origin}/llms.txt`, LLMS_TIMEOUT_MS, LLMS_MAX_BYTES);
    if (llms.status === 200 && llms.body.trim().length > 0) {
      const looksLike =
        llms.body.includes("#") ||
        /(^|\n)\s*[-*]\s/.test(llms.body) ||
        llms.body.includes("http");
      if (looksLike) {
        llmsPass = true;
        llmsDetail = "Found a readable llms.txt at the site root.";
      } else {
        llmsDetail = "An llms.txt exists but doesn't look like a valid one.";
      }
    } else {
      llmsDetail = `No llms.txt found at the site root (status ${llms.status}).`;
    }
  } catch (e) {
    llmsDetail =
      e instanceof FetchFailed ? `llms.txt check failed: ${e.message}` : "llms.txt check failed.";
  }

  /* --- schema (20: FAQ 8 / Org 7 / HowTo-or-Product 5) --- */
  const types = new Set();
  const orgs = [];
  for (const block of getJsonLdBlocks(html)) {
    try {
      walkSchema(JSON.parse(block), types, orgs);
    } catch {
      // ignore malformed JSON-LD blocks
    }
  }
  const hasFaq = types.has("FAQPage");
  const hasOrg = types.has("Organization") || types.has("LocalBusiness");
  const hasHowToProduct = types.has("HowTo") || types.has("Product");
  const schemaScore = (hasFaq ? 8 : 0) + (hasOrg ? 7 : 0) + (hasHowToProduct ? 5 : 0);
  const schemaPass = schemaScore === 20;
  const schemaFound = [...types].slice(0, 6);
  const schemaDetail = schemaPass
    ? `FAQ, Organization${types.has("LocalBusiness") ? " (LocalBusiness)" : ""} and ${
        types.has("HowTo") ? "HowTo" : "Product"
      } schema all present.`
    : schemaFound.length > 0
      ? `Found: ${schemaFound.join(", ")}. Missing: ${[
          !hasFaq && "FAQPage",
          !hasOrg && "Organization",
          !hasHowToProduct && "HowTo/Product",
        ]
          .filter(Boolean)
          .join(", ")}.`
      : "No JSON-LD structured data found on this page.";

  /* --- question H2s (15; pass at >=30% question ratio) --- */
  const h2Texts = tagContents(clean, "h2").map(cleanText).filter(Boolean);
  const questionH2s = h2Texts.filter(isQuestionHeading);
  const questionRatio = h2Texts.length > 0 ? questionH2s.length / h2Texts.length : 0;
  const questionsPass = questionRatio >= 0.3;
  const questionsDetail =
    h2Texts.length === 0
      ? "No H2 headings found on this page."
      : `${questionH2s.length} of ${h2Texts.length} H2s are phrased as questions (${Math.round(
          questionRatio * 100
        )}%).`;

  /* --- answer blocks (15; pass at >=2 blocks of 30–80 words) --- */
  const pTexts = tagContents(clean, "p").map(cleanText).filter(Boolean);
  const candidates = pTexts.slice(0, 10).filter((t) => {
    const n = wordCount(t);
    return n >= 30 && n <= 80;
  });
  const answersPass = candidates.length >= 2;
  const answersDetail =
    candidates.length === 0
      ? `Checked the first ${Math.min(pTexts.length, 10)} paragraphs — none are 30–80 words.`
      : `${candidates.length} answer-sized paragraph${candidates.length === 1 ? "" : "s"} (30–80 words) found.`;

  /* --- entity signals (15; pass at >=2 of 4) --- */
  const hasSameAs = orgs.some((o) => {
    const s = o["sameAs"];
    if (typeof s === "string") return s.trim().length > 0;
    return Array.isArray(s) && s.some((x) => typeof x === "string" && x.trim().length > 0);
  });
  const hasWiki = /wikidata\.org|wikipedia\.org/i.test(html);
  const socials = ["instagram.com", "youtube.com", "linkedin.com", "x.com", "twitter.com", "facebook.com"];
  const socialHits = socials.filter((d) => html.toLowerCase().includes(d));
  const entitySignals = [hasOrg, hasSameAs, hasWiki, socialHits.length > 0];
  const entityCount = entitySignals.filter(Boolean).length;
  const entityPass = entityCount >= 2;
  const entityDetail =
    `${entityCount} of 4 entity signals present` +
    (entityCount > 0
      ? ` (${[
          hasOrg && "Organization schema",
          hasSameAs && "sameAs links",
          hasWiki && "Wikipedia/Wikidata link",
          socialHits.length > 0 && `social links (${socialHits.length})`,
        ]
          .filter(Boolean)
          .join(", ")}).`
      : ".");

  /* --- performance (15; pass at <2.5s AND viewport meta) --- */
  const viewport = hasViewportMeta(html);
  const perfPass = durationMs < 2500 && viewport;
  const perfDetail = viewport
    ? `Page fetched in ${durationMs} ms${durationMs >= 2500 ? " — over the 2.5 s budget" : ""}; viewport meta present.`
    : `Page fetched in ${durationMs} ms; viewport meta tag missing.`;

  const score =
    (llmsPass ? 20 : 0) +
    schemaScore +
    (questionsPass ? 15 : 0) +
    (answersPass ? 15 : 0) +
    (entityPass ? 15 : 0) +
    (perfPass ? 15 : 0);

  const checks = [
    {
      id: "llms.txt",
      label: "LLMs.txt discovery file",
      pass: llmsPass,
      detail: llmsDetail,
      hint: llmsPass
        ? "Keep it updated as your content changes."
        : "Add an /llms.txt file at your site root so AI crawlers can read your content.",
    },
    {
      id: "schema.org",
      label: "Structured data (schema markup)",
      pass: schemaPass,
      detail: schemaDetail,
      hint: schemaPass
        ? "You're covered on the big three."
        : "Add FAQ, Organization, or HowTo JSON-LD schema to your page.",
    },
    {
      id: "question-headings",
      label: "Question-based headings",
      pass: questionsPass,
      detail: questionsDetail,
      hint: questionsPass
        ? "AI assistants love question-shaped headings."
        : "Rewrite some H2s as direct questions your customers actually ask.",
    },
    {
      id: "answer-blocks",
      label: "Answer-ready blocks",
      pass: answersPass,
      detail: answersDetail,
      hint: answersPass
        ? "Short, self-contained answers are citation-friendly."
        : "Add 2–3 paragraphs of 30–80 words, each answering one question directly.",
    },
    {
      id: "entity-signals",
      label: "Brand entity signals",
      pass: entityPass,
      detail: entityDetail,
      hint: entityPass
        ? "Your brand is legible as an entity."
        : "Add Organization schema with sameAs links to your social profiles and Wikipedia/Wikidata.",
    },
    {
      id: "performance",
      label: "Speed & mobile basics",
      pass: perfPass,
      detail: perfDetail,
      hint: perfPass
        ? "Fast and mobile-ready."
        : "Compress images and add a viewport meta tag to load faster on mobile.",
    },
  ];

  return {
    url: page.finalUrl,
    title: getTitle(html) || undefined,
    score,
    verdict: verdictFor(score),
    checks,
    meta: {
      durationMs,
      fetchedAt: new Date().toISOString(),
      h1Count: tagContents(clean, "h1").length,
    },
    aiMention: {
      status: "pending",
      message: "AI mention test unlocks with an API key.",
    },
  };
}

/* ------------------------------------------------------------------ */
/* Output                                                              */
/* ------------------------------------------------------------------ */

function printReport(r) {
  const icon = (pass) => (pass ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`);
  console.log(`\n${BOLD}${r.url}${RESET}${DIM} — aeo-audit v${VERSION}${RESET}\n`);
  const width = Math.max(...r.checks.map((c) => c.id.length));
  for (const c of r.checks) {
    console.log(`  ${icon(c.pass)} ${c.id.padEnd(width)}  ${DIM}${c.detail}${RESET}`);
  }
  const failures = r.checks.filter((c) => !c.pass);
  console.log(`\n  ${BOLD}SCORE: ${r.score}/100 — ${r.verdict}${RESET}`);
  if (failures.length > 0) {
    console.log(`\n${BOLD}FIXES:${RESET}`);
    for (const c of failures) {
      console.log(`  ${DIM}→${RESET} ${c.id}: ${c.hint}`);
    }
  }
  console.log(`\n${DIM}Scanned in ${r.meta.durationMs} ms. Part of the @digitaldabbi toolchain.${RESET}\n`);
}

/* ------------------------------------------------------------------ */

try {
  const report = await audit(urlArg);
  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printReport(report);
  }
  process.exit(0);
} catch (e) {
  fail(e instanceof Error ? e.message : "Audit failed unexpectedly.");
}
