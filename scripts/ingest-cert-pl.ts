#!/usr/bin/env npx tsx
/**
 * Ingestion crawler for CERT Polska (cert.pl).
 *
 * Crawls three content streams from cert.pl and inserts into the local
 * better-sqlite3 database used by the Polish Cybersecurity MCP server:
 *
 *   1. News / analyses  — cert.pl/news/ (paginated, ~33 pages)
 *   2. CVE advisories   — cert.pl/cve/  (paginated, ~15 pages)
 *   3. Publications      — cert.pl/publikacje/ (single page, PDF links)
 *
 * Each article detail page is fetched individually for full text.
 *
 * Usage:
 *   npx tsx scripts/ingest-cert-pl.ts
 *   npx tsx scripts/ingest-cert-pl.ts --dry-run    # parse without DB writes
 *   npx tsx scripts/ingest-cert-pl.ts --resume      # skip already-ingested references
 *   npx tsx scripts/ingest-cert-pl.ts --force        # drop existing data first
 *   npx tsx scripts/ingest-cert-pl.ts --pages 3      # limit listing pages per stream
 *   npx tsx scripts/ingest-cert-pl.ts --stream news  # crawl only one stream
 *
 * Environment:
 *   CERT_PL_DB_PATH — SQLite database path (default: data/cert_pl.db)
 *
 * Rate limit: 1 500 ms between HTTP requests (respectful crawling).
 * Retry: up to 3 attempts per request with exponential backoff.
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import type { AnyNode, Element } from "domhandler";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Config & CLI flags
// ---------------------------------------------------------------------------

const DB_PATH = process.env["CERT_PL_DB_PATH"] ?? "data/cert_pl.db";
const BASE = "https://cert.pl";
const RATE_LIMIT_MS = 1_500;
const MAX_RETRIES = 3;
const BACKOFF_BASE_MS = 2_000;
const USER_AGENT =
  "AnsvarCERTPlCrawler/1.0 (+https://github.com/Ansvar-Systems/polish-cybersecurity-mcp)";

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const resume = args.includes("--resume");
const force = args.includes("--force");

function flagValue(name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

const maxPages = parseInt(flagValue("--pages") ?? "0", 10) || 0; // 0 = unlimited
const streamFilter = flagValue("--stream"); // "news" | "cve" | "publications"

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(msg: string): void {
  const ts = new Date().toISOString();
  process.stderr.write(`[${ts}] ${msg}\n`);
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

async function rateLimit(): Promise<void> {
  const elapsed = Date.now() - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await new Promise((r) => setTimeout(r, RATE_LIMIT_MS - elapsed));
  }
}

async function fetchPage(url: string): Promise<string> {
  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    await rateLimit();
    lastRequestTime = Date.now();

    try {
      const resp = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml",
          "Accept-Language": "pl,en;q=0.5",
        },
        signal: AbortSignal.timeout(30_000),
      });

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }

      return await resp.text();
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      log(
        `  Attempt ${attempt}/${MAX_RETRIES} failed for ${url}: ${lastError.message}`,
      );

      if (attempt < MAX_RETRIES) {
        const backoff = BACKOFF_BASE_MS * Math.pow(2, attempt - 1);
        await new Promise((r) => setTimeout(r, backoff));
      }
    }
  }

  throw lastError ?? new Error(`Failed to fetch ${url}`);
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/** Normalise Polish date string ("18 marca 2026") to ISO date. */
function parsePolishDate(raw: string): string | null {
  const months: Record<string, string> = {
    stycznia: "01",
    lutego: "02",
    marca: "03",
    kwietnia: "04",
    maja: "05",
    czerwca: "06",
    lipca: "07",
    sierpnia: "08",
    wrzesnia: "09",
    września: "09",
    pazdziernika: "10",
    października: "10",
    listopada: "11",
    grudnia: "12",
  };

  const m = raw
    .trim()
    .match(/(\d{1,2})\s+(\S+)\s+(\d{4})/);
  if (!m) return null;

  const day = m[1]!.padStart(2, "0");
  const monthName = m[2]!.toLowerCase();
  const year = m[3]!;
  const month = months[monthName];
  if (!month) return null;

  return `${year}-${month}-${day}`;
}

/** Extract visible text from a cheerio element, collapsing whitespace. */
function cleanText($el: cheerio.Cheerio<AnyNode>): string {
  return $el
    .text()
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Extract tags from an article listing entry or detail page.
 * Tags appear as <a> elements whose href matches /tag/.
 */
function extractTags(
  $: cheerio.CheerioAPI,
  scope: cheerio.Cheerio<AnyNode>,
): string[] {
  const tags: string[] = [];
  scope.find('a[href*="/tag/"]').each((_, el) => {
    const text = $(el).text().replace(/^#/, "").trim();
    if (text) tags.push(text);
  });
  return tags;
}

// ---------------------------------------------------------------------------
// Types for intermediate parsed data
// ---------------------------------------------------------------------------

interface ListingEntry {
  url: string;       // absolute URL to article detail
  title: string;
  dateRaw: string;   // raw Polish date
  tags: string[];
  summary: string;
}

interface ParsedArticle {
  reference: string;
  title: string;
  date: string | null;
  tags: string[];
  summary: string;
  fullText: string;
  cveIds: string[];
  affectedProducts: string[];
  severity: string | null;
  type: "advisory" | "guidance";
}

// ---------------------------------------------------------------------------
// Listing page parsers
// ---------------------------------------------------------------------------

/**
 * Parse a paginated listing page (news or cve).
 * Returns article stub entries + whether a next page exists.
 */
function parseListingPage(
  html: string,
  baseUrl: string,
): { entries: ListingEntry[]; hasNext: boolean; nextUrl: string | null } {
  const $ = cheerio.load(html);
  const entries: ListingEntry[] = [];

  // Each article block lives in an <a class="post-list-wrapper"> or within
  // a structure that has date, author, tag links, then an <a> with <h4>.
  // The site groups each article's metadata (date, author, tags) as siblings
  // before the <a> that contains the <h4> title and summary.
  //
  // Strategy: find all <h4> inside links, then walk up to gather metadata.

  // Approach: iterate all <a> tags containing an <h4>
  $("a:has(h4)").each((_, linkEl) => {
    const $link = $(linkEl);
    const href = $link.attr("href");
    if (!href) return;

    const title = cleanText($link.find("h4"));
    if (!title) return;

    const url = new URL(href, baseUrl).toString();

    // Summary is text after the <h4>, inside the same <a>, excluding the h4 itself
    const summaryParts: string[] = [];
    $link.contents().each((_, node) => {
      if (node.type === "text") {
        const t = (node as unknown as { data: string }).data?.trim();
        if (t && t !== "Czytaj dalej" && t !== title) {
          summaryParts.push(t);
        }
      }
    });
    // Also check for <p> inside the link
    $link.find("p").each((_, p) => {
      const t = $(p).text().trim();
      if (t && t !== "Czytaj dalej") summaryParts.push(t);
    });
    const summary = summaryParts.join(" ").trim();

    // Date and tags: look at preceding siblings of the <a> element
    let dateRaw = "";
    const tags: string[] = [];

    const parent = $link.parent();
    let sibling = $link.prev();

    // Walk backwards through siblings to find date text and tag links
    while (sibling.length > 0) {
      // Check for tag links
      sibling.find('a[href*="/tag/"]').each((_, tagEl) => {
        const t = $(tagEl).text().replace(/^#/, "").trim();
        if (t) tags.push(t);
      });

      // Check for date-like text
      const sibText = cleanText(sibling);
      if (/\d{1,2}\s+\S+\s+\d{4}/.test(sibText) && !dateRaw) {
        const dateMatch = sibText.match(/(\d{1,2}\s+\S+\s+\d{4})/);
        if (dateMatch) dateRaw = dateMatch[1]!;
      }

      sibling = sibling.prev();
    }

    // Also check parent for date text nodes directly
    if (!dateRaw) {
      parent.contents().each((_, node) => {
        if (node.type === "text" && !dateRaw) {
          const t = (node as unknown as { data: string }).data?.trim() ?? "";
          const dm = t.match(/(\d{1,2}\s+\S+\s+\d{4})/);
          if (dm) dateRaw = dm[1]!;
        }
      });
    }

    entries.push({ url, title, dateRaw, tags, summary });
  });

  // Pagination: look for a "next" link (» or following page number)
  let hasNext = false;
  let nextUrl: string | null = null;

  // The pagination typically renders as: [1] [2] ... [N] [»]
  // The » link points to the next page
  $('a').each((_, el) => {
    const text = $(el).text().trim();
    if (text === "»" || text === "›") {
      const href = $(el).attr("href");
      if (href) {
        hasNext = true;
        nextUrl = new URL(href, baseUrl).toString();
      }
    }
  });

  return { entries, hasNext, nextUrl };
}

// ---------------------------------------------------------------------------
// Article detail parser
// ---------------------------------------------------------------------------

function parseArticleDetail(html: string, url: string): ParsedArticle {
  const $ = cheerio.load(html);

  // Title: first <h1> in content
  const title = cleanText($("h1").first());

  // Date: text matching "DD month YYYY" pattern near the top
  let dateRaw = "";
  // Look for date in byline area (text before first tag link or author link)
  $("body").find("*").each((_, el) => {
    if (dateRaw) return;
    const text = $(el)
      .contents()
      .filter((_, n) => n.type === "text")
      .text();
    const dm = text.match(/(\d{1,2}\s+(?:stycznia|lutego|marca|kwietnia|maja|czerwca|lipca|sierpnia|wrzesnia|września|pazdziernika|października|listopada|grudnia)\s+\d{4})/i);
    if (dm) dateRaw = dm[1]!;
  });
  const date = parsePolishDate(dateRaw);

  // Tags
  const tags = extractTags($, $("body"));

  // CVE references from body text
  const bodyHtml = $.html() ?? "";
  const cveMatches = bodyHtml.match(/CVE-\d{4}-\d{4,}/g);
  const cveIds = cveMatches ? [...new Set(cveMatches)] : [];

  // Determine type: CVE advisory vs general guidance/news
  const isCve = url.includes("/CVE-") || cveIds.length > 0;
  const hasWarningTag =
    tags.some((t) => ["ostrzeżenie", "ostrzezenie", "podatność", "podatnosc", "cve"].includes(t.toLowerCase()));
  const type: "advisory" | "guidance" =
    isCve || hasWarningTag ? "advisory" : "guidance";

  // Full text: collect all paragraphs, headings, list items, table cells
  // from the article body (skip nav, footer, sidebar)
  const contentSelectors = [
    "article",
    ".post-content",
    ".entry-content",
    ".content",
    "main",
  ];

  let $content: cheerio.Cheerio<AnyNode> | null = null;
  for (const sel of contentSelectors) {
    const $c = $(sel);
    if ($c.length > 0) {
      $content = $c.first();
      break;
    }
  }

  // Fallback: use the body but strip nav/footer/header
  if (!$content || $content.length === 0) {
    $content = $("body");
    $content.find("nav, footer, header, script, style, noscript").remove();
  }

  // Build structured full text
  const textParts: string[] = [];

  $content.find("h1, h2, h3, h4, h5, h6, p, li, td, th, blockquote, pre, code, dt, dd").each(
    (_, el) => {
      const tag = (el as Element).tagName?.toLowerCase() ?? "";
      const text = $(el).text().trim();
      if (!text) return;

      // Skip nav/menu items
      if ($(el).closest("nav, footer, header").length > 0) return;

      if (tag.startsWith("h")) {
        textParts.push(`\n${text}\n`);
      } else if (tag === "li") {
        textParts.push(`- ${text}`);
      } else if (tag === "pre" || tag === "code") {
        // Skip large code blocks but keep short ones
        if (text.length < 500) textParts.push(text);
      } else {
        textParts.push(text);
      }
    },
  );

  const fullText = textParts
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  // Summary: first meaningful paragraph (>40 chars)
  let summary = "";
  $content.find("p").each((_, el) => {
    if (summary) return;
    const t = $(el).text().trim();
    if (t.length > 40) summary = t;
  });

  // Affected products (for CVE advisories): look for product/vendor mentions
  const affectedProducts: string[] = [];
  if (type === "advisory") {
    // Look for structured fields like "Produkt:", "Oprogramowanie:", "Wersje:"
    const productPatterns = [
      /(?:Produkt|Product|Oprogramowanie|Software)\s*[:—]\s*(.+)/gi,
      /(?:Dostawca|Vendor)\s*[:—]\s*(.+)/gi,
    ];
    for (const pattern of productPatterns) {
      let pm;
      while ((pm = pattern.exec(fullText)) !== null) {
        const product = pm[1]!.trim();
        if (product && !affectedProducts.includes(product)) {
          affectedProducts.push(product);
        }
      }
    }
  }

  // Severity: check for CVSS scores or severity keywords
  let severity: string | null = null;
  const cvssMatch = fullText.match(/CVSS[^:]*:\s*(\d+\.?\d*)/i);
  if (cvssMatch) {
    const score = parseFloat(cvssMatch[1]!);
    if (score >= 9.0) severity = "critical";
    else if (score >= 7.0) severity = "high";
    else if (score >= 4.0) severity = "medium";
    else severity = "low";
  }
  if (!severity) {
    if (/krytyczn/i.test(fullText)) severity = "critical";
    else if (/wysok/i.test(fullText)) severity = "high";
  }

  // Reference: build from URL slug or CVE ID
  let reference: string;
  if (cveIds.length > 0) {
    reference = `CERT-PL-${cveIds[0]}`;
  } else {
    // Extract slug from URL: /posts/YYYY/MM/slug/ → CERT-PL-NEWS-YYYY-slug
    const slugMatch = url.match(/\/posts\/(\d{4})\/(\d{2})\/([^/]+)/);
    if (slugMatch) {
      const year = slugMatch[1]!;
      const slug = slugMatch[3]!;
      reference = `CERT-PL-NEWS-${year}-${slug}`;
    } else {
      reference = `CERT-PL-${Date.now()}`;
    }
  }

  return {
    reference,
    title,
    date,
    tags,
    summary,
    fullText,
    cveIds,
    affectedProducts,
    severity,
    type,
  };
}

// ---------------------------------------------------------------------------
// Publications parser (single page, PDF-linked reports)
// ---------------------------------------------------------------------------

interface PublicationEntry {
  title: string;
  url: string;
  date: string | null;
  category: string;
}

function parsePublicationsPage(html: string): PublicationEntry[] {
  const $ = cheerio.load(html);
  const entries: PublicationEntry[] = [];

  // Publications page lists reports grouped by category.
  // Each entry has a title and a link (often to a PDF or a blog post).
  $("a").each((_, el) => {
    const $a = $(el);
    const href = $a.attr("href");
    const title = cleanText($a);

    if (!href || !title) return;
    if (title.length < 10) return;

    // Filter to publications content (PDFs, report posts)
    const isReport =
      href.includes("/uploads/") ||
      href.includes("/posts/") ||
      href.endsWith(".pdf");
    const isNavLink =
      href.includes("/tag/") ||
      href.includes("/o-nas") ||
      href.includes("/kontakt") ||
      href.includes("/praca") ||
      href === "/" ||
      href === "#";

    if (!isReport || isNavLink) return;

    // Try to extract year from URL or title
    let date: string | null = null;
    const yearMatch = title.match(/(\d{4})/);
    if (yearMatch) {
      date = `${yearMatch[1]}-01-01`;
    }
    const urlYearMatch = href.match(/\/(\d{4})\//);
    if (urlYearMatch && !date) {
      date = `${urlYearMatch[1]}-01-01`;
    }

    // Categorise
    let category = "report";
    if (/raport miesi/i.test(title)) category = "monthly_report";
    else if (/raport roczny|krajobraz/i.test(title)) category = "annual_report";
    else if (/poradnik|rekomendacj/i.test(title)) category = "guide";
    else if (/incydent|sektor/i.test(title)) category = "incident_report";

    const fullUrl = new URL(href, BASE).toString();

    // Avoid duplicates by URL
    if (!entries.some((e) => e.url === fullUrl)) {
      entries.push({ title, url: fullUrl, date, category });
    }
  });

  return entries;
}

// ---------------------------------------------------------------------------
// Database operations
// ---------------------------------------------------------------------------

function initDb(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  if (force && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    log(`Deleted existing database at ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  return db;
}

function existingReferences(db: Database.Database): Set<string> {
  const refs = new Set<string>();
  const rows = db
    .prepare("SELECT reference FROM guidance")
    .all() as { reference: string }[];
  for (const r of rows) refs.add(r.reference);

  const advRows = db
    .prepare("SELECT reference FROM advisories")
    .all() as { reference: string }[];
  for (const r of advRows) refs.add(r.reference);

  return refs;
}

function insertAdvisory(
  db: Database.Database,
  article: ParsedArticle,
): void {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    article.reference,
    article.title,
    article.date,
    article.severity,
    article.affectedProducts.length > 0
      ? JSON.stringify(article.affectedProducts)
      : null,
    article.summary || null,
    article.fullText,
    article.cveIds.length > 0 ? JSON.stringify(article.cveIds) : null,
  );
}

function insertGuidance(
  db: Database.Database,
  article: ParsedArticle,
): void {
  // Determine series from tags and content
  let series = "CERT-PL";
  if (article.tags.some((t) => /ksc/i.test(t))) series = "KSC";
  else if (article.tags.some((t) => /nis2/i.test(t))) series = "NIS2";

  // Determine type from tags
  let docType = "technical_guideline";
  if (article.tags.some((t) => /poradnik/i.test(t))) docType = "technical_guideline";
  else if (article.tags.some((t) => /rekomendacj/i.test(t))) docType = "recommendation";
  else if (article.tags.some((t) => /raport/i.test(t))) docType = "report";
  else if (article.tags.some((t) => /analiz|analysis|dfir|malware/i.test(t))) docType = "analysis";
  else if (article.tags.some((t) => /informacja/i.test(t))) docType = "information";

  const stmt = db.prepare(`
    INSERT OR REPLACE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    article.reference,
    article.title,
    null, // title_en — not available from Polish-language crawl
    article.date,
    docType,
    series,
    article.summary || null,
    article.fullText,
    article.tags.length > 0 ? JSON.stringify(article.tags) : null,
    "current",
  );
}

function insertPublication(
  db: Database.Database,
  pub: PublicationEntry,
): void {
  // Publications go into the guidance table as type "report" or "guide"
  const reference = `CERT-PL-PUB-${pub.title.replace(/[^a-zA-Z0-9]/g, "-").replace(/-+/g, "-").substring(0, 80)}`;

  const stmt = db.prepare(`
    INSERT OR IGNORE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    reference,
    pub.title,
    null,
    pub.date,
    pub.category,
    "CERT-PL",
    `Publikacja CERT Polska: ${pub.title}`,
    `Publikacja dostepna pod adresem: ${pub.url}\n\n${pub.title}`,
    JSON.stringify(["publikacja", pub.category]),
    "current",
  );
}

function updateFrameworkCounts(db: Database.Database): void {
  // Count guidance documents per series and update framework table
  const series = ["CERT-PL", "KSC", "NIS2"];
  const frameworkMapping: Record<string, string> = {
    "CERT-PL": "cert-polska-guides",
    KSC: "ksc-framework",
    NIS2: "nis2-pl",
  };

  for (const s of series) {
    const row = db
      .prepare("SELECT count(*) as cnt FROM guidance WHERE series = ?")
      .get(s) as { cnt: number } | undefined;
    const count = row?.cnt ?? 0;
    const fwId = frameworkMapping[s];
    if (fwId) {
      db.prepare("UPDATE frameworks SET document_count = ? WHERE id = ?").run(
        count,
        fwId,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Crawl orchestration
// ---------------------------------------------------------------------------

interface CrawlStats {
  listingPagesFetched: number;
  articlesFetched: number;
  advisoriesInserted: number;
  guidanceInserted: number;
  publicationsInserted: number;
  skipped: number;
  errors: number;
}

async function crawlPaginatedStream(
  db: Database.Database | null,
  startUrl: string,
  streamName: string,
  existing: Set<string>,
  stats: CrawlStats,
): Promise<void> {
  log(`--- Crawling ${streamName} from ${startUrl} ---`);

  let currentUrl: string | null = startUrl;
  let pageNum = 0;

  while (currentUrl) {
    pageNum++;
    if (maxPages > 0 && pageNum > maxPages) {
      log(`  Reached page limit (${maxPages}), stopping ${streamName} stream`);
      break;
    }

    log(`  Fetching listing page ${pageNum}: ${currentUrl}`);
    let html: string;
    try {
      html = await fetchPage(currentUrl);
      stats.listingPagesFetched++;
    } catch (err) {
      log(
        `  Failed to fetch listing page: ${err instanceof Error ? err.message : String(err)}`,
      );
      stats.errors++;
      break;
    }

    const { entries, hasNext, nextUrl } = parseListingPage(html, currentUrl);
    log(`  Found ${entries.length} entries on page ${pageNum}`);

    if (entries.length === 0) {
      log(`  No entries found, stopping`);
      break;
    }

    for (const entry of entries) {
      // Build a preliminary reference to check resume
      const slugMatch = entry.url.match(/\/posts\/(\d{4})\/(\d{2})\/([^/]+)/);
      let prelimRef = "";
      if (slugMatch) {
        const slug = slugMatch[3]!;
        const year = slugMatch[1]!;
        if (slug.startsWith("CVE-")) {
          prelimRef = `CERT-PL-${slug}`;
        } else {
          prelimRef = `CERT-PL-NEWS-${year}-${slug}`;
        }
      }

      if (resume && prelimRef && existing.has(prelimRef)) {
        log(`  Skipping (already ingested): ${prelimRef}`);
        stats.skipped++;
        continue;
      }

      log(`  Fetching article: ${entry.title.substring(0, 70)}...`);
      let articleHtml: string;
      try {
        articleHtml = await fetchPage(entry.url);
        stats.articlesFetched++;
      } catch (err) {
        log(
          `  Failed to fetch article ${entry.url}: ${err instanceof Error ? err.message : String(err)}`,
        );
        stats.errors++;
        continue;
      }

      let article: ParsedArticle;
      try {
        article = parseArticleDetail(articleHtml, entry.url);
      } catch (err) {
        log(
          `  Failed to parse article ${entry.url}: ${err instanceof Error ? err.message : String(err)}`,
        );
        stats.errors++;
        continue;
      }

      // Use listing entry data to fill gaps
      if (!article.date && entry.dateRaw) {
        article.date = parsePolishDate(entry.dateRaw);
      }
      if (article.tags.length === 0 && entry.tags.length > 0) {
        article.tags = entry.tags;
      }
      if (!article.summary && entry.summary) {
        article.summary = entry.summary;
      }

      // Second resume check with actual reference
      if (resume && existing.has(article.reference)) {
        log(`  Skipping (already ingested): ${article.reference}`);
        stats.skipped++;
        continue;
      }

      if (dryRun) {
        log(
          `  [DRY RUN] Would insert ${article.type}: ${article.reference} — ${article.title.substring(0, 60)}`,
        );
        if (article.type === "advisory") stats.advisoriesInserted++;
        else stats.guidanceInserted++;
        continue;
      }

      if (!db) continue;

      try {
        if (article.type === "advisory") {
          insertAdvisory(db, article);
          stats.advisoriesInserted++;
          existing.add(article.reference);
          log(`  Inserted advisory: ${article.reference}`);
        } else {
          insertGuidance(db, article);
          stats.guidanceInserted++;
          existing.add(article.reference);
          log(`  Inserted guidance: ${article.reference}`);
        }
      } catch (err) {
        log(
          `  DB insert error for ${article.reference}: ${err instanceof Error ? err.message : String(err)}`,
        );
        stats.errors++;
      }
    }

    currentUrl = hasNext ? nextUrl : null;
  }
}

async function crawlPublications(
  db: Database.Database | null,
  existing: Set<string>,
  stats: CrawlStats,
): Promise<void> {
  log("--- Crawling publications from cert.pl/publikacje/ ---");

  let html: string;
  try {
    html = await fetchPage(`${BASE}/publikacje/`);
    stats.listingPagesFetched++;
  } catch (err) {
    log(
      `  Failed to fetch publications page: ${err instanceof Error ? err.message : String(err)}`,
    );
    stats.errors++;
    return;
  }

  const publications = parsePublicationsPage(html);
  log(`  Found ${publications.length} publications`);

  for (const pub of publications) {
    const reference = `CERT-PL-PUB-${pub.title.replace(/[^a-zA-Z0-9]/g, "-").replace(/-+/g, "-").substring(0, 80)}`;

    if (resume && existing.has(reference)) {
      log(`  Skipping (already ingested): ${reference}`);
      stats.skipped++;
      continue;
    }

    if (dryRun) {
      log(`  [DRY RUN] Would insert publication: ${pub.title.substring(0, 60)}`);
      stats.publicationsInserted++;
      continue;
    }

    if (!db) continue;

    try {
      insertPublication(db, pub);
      stats.publicationsInserted++;
      existing.add(reference);
      log(`  Inserted publication: ${pub.title.substring(0, 60)}`);
    } catch (err) {
      log(
        `  DB insert error for publication: ${err instanceof Error ? err.message : String(err)}`,
      );
      stats.errors++;
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  log("CERT Polska ingestion crawler starting");
  log(`  Database: ${DB_PATH}`);
  log(
    `  Flags: ${[dryRun && "--dry-run", resume && "--resume", force && "--force", maxPages && `--pages ${maxPages}`, streamFilter && `--stream ${streamFilter}`].filter(Boolean).join(", ") || "(none)"}`,
  );

  const db = dryRun ? null : initDb();
  if (!dryRun && db) {
    log(`Database initialised at ${DB_PATH}`);
  }

  const existing = db ? existingReferences(db) : new Set<string>();
  if (resume) {
    log(`  Resume mode: ${existing.size} existing references found`);
  }

  const stats: CrawlStats = {
    listingPagesFetched: 0,
    articlesFetched: 0,
    advisoriesInserted: 0,
    guidanceInserted: 0,
    publicationsInserted: 0,
    skipped: 0,
    errors: 0,
  };

  // Stream 1: News / analyses
  if (!streamFilter || streamFilter === "news") {
    await crawlPaginatedStream(
      db,
      `${BASE}/news/`,
      "news",
      existing,
      stats,
    );
  }

  // Stream 2: CVE advisories
  if (!streamFilter || streamFilter === "cve") {
    await crawlPaginatedStream(
      db,
      `${BASE}/cve/`,
      "cve",
      existing,
      stats,
    );
  }

  // Stream 3: Publications
  if (!streamFilter || streamFilter === "publications") {
    await crawlPublications(db, existing, stats);
  }

  // Update framework document counts
  if (db && !dryRun) {
    updateFrameworkCounts(db);
    log("Updated framework document counts");
  }

  // Final summary
  const totalInserted =
    stats.advisoriesInserted + stats.guidanceInserted + stats.publicationsInserted;

  log("\n=== Ingestion complete ===");
  log(`  Listing pages fetched: ${stats.listingPagesFetched}`);
  log(`  Articles fetched:      ${stats.articlesFetched}`);
  log(`  Advisories inserted:   ${stats.advisoriesInserted}`);
  log(`  Guidance inserted:     ${stats.guidanceInserted}`);
  log(`  Publications inserted: ${stats.publicationsInserted}`);
  log(`  Total inserted:        ${totalInserted}`);
  log(`  Skipped (resume):      ${stats.skipped}`);
  log(`  Errors:                ${stats.errors}`);

  if (db && !dryRun) {
    const guidanceCount = (
      db.prepare("SELECT count(*) as cnt FROM guidance").get() as {
        cnt: number;
      }
    ).cnt;
    const advisoryCount = (
      db.prepare("SELECT count(*) as cnt FROM advisories").get() as {
        cnt: number;
      }
    ).cnt;

    log(`\nDatabase totals:`);
    log(`  Guidance:    ${guidanceCount}`);
    log(`  Advisories:  ${advisoryCount}`);

    db.close();
  }

  log(`\nDone.`);

  if (stats.errors > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  log(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
});
