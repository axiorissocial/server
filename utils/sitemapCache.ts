import fs from 'fs/promises';
import path from 'path';

const CACHE_DIR = path.join(process.cwd(), 'cache');
const CACHE_FILE = path.join(CACHE_DIR, 'sitemap.xml');

type UrlEntry = { loc: string; lastmod?: string; changefreq?: string; priority?: string };

let urlMap = new Map<string, UrlEntry>();

export async function initSitemapCache(initialUrls: UrlEntry[] = []) {
  try {
    await fs.mkdir(CACHE_DIR, { recursive: true });
  } catch (e) {}

  for (const u of initialUrls) {
    urlMap.set(u.loc, u);
  }

  await writeCache();
}

export function addUrl(entry: UrlEntry) {
  urlMap.set(entry.loc, entry);
  writeCache().catch(err => console.error('Failed to write sitemap cache:', err));
}

export function removeUrl(loc: string) {
  if (urlMap.delete(loc)) {
    writeCache().catch(err => console.error('Failed to write sitemap cache:', err));
  }
}

export async function rebuildCache(entries: UrlEntry[]) {
  urlMap = new Map(entries.map(e => [e.loc, e]));
  await writeCache();
}

async function writeCache() {
  const entries = Array.from(urlMap.values()).sort((a, b) => a.loc.localeCompare(b.loc));

  const escapeXml = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');

  const lines: string[] = [];
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">');

  for (const entry of entries) {
    lines.push('  <url>');
    lines.push(`    <loc>${escapeXml(entry.loc)}</loc>`);
    if (entry.lastmod) lines.push(`    <lastmod>${escapeXml(entry.lastmod)}</lastmod>`);
    if (entry.changefreq) lines.push(`    <changefreq>${escapeXml(entry.changefreq)}</changefreq>`);
    if (entry.priority) lines.push(`    <priority>${escapeXml(entry.priority)}</priority>`);
    lines.push('  </url>');
  }

  lines.push('</urlset>');

  await fs.mkdir(CACHE_DIR, { recursive: true });
  const content = lines.join('\r\n');
  await fs.writeFile(CACHE_FILE, content, 'utf8');
}

export function getCachedSitemapPath() {
  return CACHE_FILE;
}
