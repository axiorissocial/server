import { Router, Request, Response } from 'express';
import { prisma } from '../index.js';
import fs from 'fs';
import { getCachedSitemapPath } from '../utils/sitemapCache.js';

const router = Router();

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

const formatDate = (d?: Date | null) => {
  if (!d) return undefined;
  return d.toISOString();
};

router.get('/sitemap.xml', async (req: Request, res: Response) => {
  try {
    const cachePath = getCachedSitemapPath();
    if (fs.existsSync(cachePath)) {
      const xml = fs.readFileSync(cachePath, 'utf8');
      res.header('Content-Type', 'application/xml');
      res.set('Cache-Control', 'public, max-age=60, s-maxage=300');
      res.set('X-Cache', 'HIT');
      res.send(xml);
      return;
    }
  } catch (err) {
    console.error('Error while checking sitemap cache:', err);
  }

  const base = FRONTEND_URL.replace(/\/$/, '');

  const urls: Array<{ loc: string; lastmod?: string; changefreq?: string; priority?: string }> = [
    { loc: `${base}/`, changefreq: 'daily', priority: '1.0' },
  ];

  try {
    const posts = await prisma.post.findMany({
      where: { isPrivate: false },
      select: { id: true, slug: true, updatedAt: true, createdAt: true },
      orderBy: { updatedAt: 'desc' },
      take: 5000,
    });

    for (const p of posts) {
      const lastmod = formatDate(p.updatedAt ?? p.createdAt);
      if (p.slug) {
        urls.push({ loc: `${base}/post/${encodeURIComponent(p.slug)}`, lastmod, changefreq: 'weekly', priority: '0.8' });
      }
      urls.push({ loc: `${base}/post/${encodeURIComponent(p.id)}`, lastmod, changefreq: 'weekly', priority: '0.8' });
    }

    const users = await prisma.user.findMany({
      where: { isPrivate: false },
      select: { username: true, updatedAt: true },
      orderBy: { updatedAt: 'desc' },
      take: 5000,
    });

    for (const u of users) {
      urls.push({ loc: `${base}/profile/${encodeURIComponent(u.username)}`, lastmod: formatDate(u.updatedAt), changefreq: 'weekly', priority: '0.6' });
      urls.push({ loc: `${base}/profile/@${encodeURIComponent(u.username)}`, lastmod: formatDate(u.updatedAt), changefreq: 'weekly', priority: '0.6' });
    }

    const tags = await prisma.hashtag.findMany({
      select: { tag: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
      take: 5000,
    });

    for (const t of tags) {
      urls.push({ loc: `${base}/hashtags/${encodeURIComponent(t.tag)}`, lastmod: formatDate(t.createdAt), changefreq: 'weekly', priority: '0.5' });
    }

    const xmlParts: string[] = [];
    xmlParts.push('<?xml version="1.0" encoding="UTF-8"?>');
    xmlParts.push('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">');

    for (const u of urls) {
      xmlParts.push('  <url>');
      xmlParts.push(`    <loc>${u.loc}</loc>`);
      if (u.lastmod) xmlParts.push(`    <lastmod>${u.lastmod}</lastmod>`);
      if (u.changefreq) xmlParts.push(`    <changefreq>${u.changefreq}</changefreq>`);
      if (u.priority) xmlParts.push(`    <priority>${u.priority}</priority>`);
      xmlParts.push('  </url>');
    }

    xmlParts.push('</urlset>');

    const xml = xmlParts.join('\r\n');
    res.header('Content-Type', 'application/xml');
    res.set('Cache-Control', 'public, max-age=60, s-maxage=300');
    res.set('X-Cache', 'MISS');
    res.send(xml);
  } catch (error) {
    console.error('Failed to generate sitemap:', error);
    res.status(500).send('Failed to generate sitemap');
  }
});

export default router;
