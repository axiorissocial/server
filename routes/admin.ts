import { Router, Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { prisma } from '../index.js';
import { awardXp } from '../utils/leveling.js';
import { addUrl, removeUrl } from '../utils/sitemapCache.js';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();

const deletePostMediaFiles = async (postId: string) => {
  try {
    const mediaDir = path.join(process.cwd(), 'public', 'uploads', 'media', postId);
    if (fs.existsSync(mediaDir)) {
      fs.rmSync(mediaDir, { recursive: true, force: true });
      console.log(`Deleted media directory for post: ${postId}`);
    }
  } catch (error) {
    console.error('Failed to delete media for post %s:', postId, error);
  }
};

router.get('/admin/users', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    const allowedPageSizes = [10, 50, 100];
    const rawPage = parseInt(req.query.page as string, 10);
    const rawLimit = parseInt(req.query.limit as string, 10);
    const searchTerm = typeof req.query.search === 'string' ? req.query.search.trim() : '';

    const page = Number.isFinite(rawPage) && rawPage > 0 ? rawPage : 1;
    const limit = allowedPageSizes.includes(rawLimit) ? rawLimit : allowedPageSizes[0];
    const skip = (page - 1) * limit;

    const where: any = {};

    if (searchTerm) {
      where.OR = [
  { username: { contains: searchTerm } },
  { email: { contains: searchTerm } },
        { id: searchTerm }
      ];
    }

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        select: {
          id: true,
          username: true,
          email: true,
          isAdmin: true,
          isPrivate: true,
          createdAt: true
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit
      }),
      prisma.user.count({ where })
    ]);

    res.json({
      users,
      total,
      pagination: {
        page,
        limit,
        total,
        pages: Math.max(1, Math.ceil(total / limit))
      }
    });
  } catch (error) {
    console.error('Error fetching users for admin:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

router.patch('/admin/user/:id/ban', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const admin = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!admin || !admin.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    const { id } = req.params;
    const { reason } = req.body;
    
    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.isAdmin) return res.status(403).json({ error: 'Cannot ban admin users' });

    const updated = await prisma.user.update({ 
      where: { id }, 
      data: { 
        isBanned: true,
        bannedAt: new Date(),
        banReason: reason || 'Violation of community guidelines'
      } 
    });
    
    try {
      const base = (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
      removeUrl(`${base}/profile/${encodeURIComponent(updated.username)}`);
      removeUrl(`${base}/profile/@${encodeURIComponent(updated.username)}`);
    } catch (err) {
      console.error('Failed to update sitemap cache after banning user:', err);
    }
    
    res.json({ message: 'User banned', user: { id: updated.id, username: updated.username }, bannedAt: updated.bannedAt, banReason: updated.banReason });
  } catch (error) {
    console.error('Error banning user:', error);
    res.status(500).json({ error: 'Failed to ban user' });
  }
});

router.patch('/admin/user/:id/unban', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const admin = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!admin || !admin.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    const { id } = req.params;
    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) return res.status(404).json({ error: 'User not found' });

    const updated = await prisma.user.update({ 
      where: { id }, 
      data: { 
        isBanned: false,
        bannedAt: null,
        banReason: null
      } 
    });
    
    try {
      const base = (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
      addUrl({ loc: `${base}/profile/${encodeURIComponent(updated.username)}`, lastmod: updated.createdAt?.toISOString() ?? new Date().toISOString(), changefreq: 'weekly', priority: '0.6' });
      addUrl({ loc: `${base}/profile/@${encodeURIComponent(updated.username)}`, lastmod: updated.createdAt?.toISOString() ?? new Date().toISOString(), changefreq: 'weekly', priority: '0.6' });
    } catch (err) {
      console.error('Failed to update sitemap cache after unbanning user:', err);
    }
    
    res.json({ message: 'User unbanned', user: { id: updated.id, username: updated.username } });
  } catch (error) {
    console.error('Error unbanning user:', error);
    res.status(500).json({ error: 'Failed to unban user' });
  }
});

router.delete('/admin/user/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const admin = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!admin || !admin.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    const { id } = req.params;
    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) return res.status(404).json({ error: 'User not found' });

    try {
      const avatarsDir = path.join(process.cwd(), 'public', 'uploads', 'avatars');
      if (fs.existsSync(avatarsDir)) {
        const files = fs.readdirSync(avatarsDir);
        files.forEach(file => {
          if (file.startsWith(id + '-')) {
            try { fs.unlinkSync(path.join(avatarsDir, file)); } catch (e) { /* ignore */ }
          }
        });
      }
    } catch (err) {
      console.error('Failed to cleanup avatar files for user:', err);
    }

    try {
      const posts = await prisma.post.findMany({ where: { userId: id }, select: { id: true } });
      for (const p of posts) {
        await deletePostMediaFiles(p.id);
      }
    } catch (err) {
      console.error('Failed to cleanup post media for user:', err);
    }

    const deletedUser = await prisma.user.delete({ where: { id } });
    try {
      const base = (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
      removeUrl(`${base}/profile/${encodeURIComponent(deletedUser.username)}`);
      removeUrl(`${base}/profile/@${encodeURIComponent(deletedUser.username)}`);
    } catch (err) {
      console.error('Failed to update sitemap cache after deleting user:', err);
    }

    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

router.delete('/admin/post/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const admin = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!admin || !admin.isAdmin) return res.status(403).json({ error: 'Admin access required' });

    const { id } = req.params;

    const existingPost = await prisma.post.findUnique({ where: { id } });
    if (!existingPost) return res.status(404).json({ error: 'Post not found' });

    await deletePostMediaFiles(id);

    await prisma.like.deleteMany({ where: { postId: id } });

    try {
      const reports = await prisma.report.findMany({ where: { postId: id }, include: { reporter: { select: { id: true } } } });
      for (const r of reports) {
        try {
          await awardXp(r.reporter.id, 25, 'report_resulted_in_admin_deletion', { sourceType: 'report_admin_deletion', sourceId: r.id });
        } catch (err) {
          console.error('Failed to award XP to reporter on admin deletion:', err);
        }
      }
    } catch (err) {
      console.error('Failed to find reports for post before deletion:', err);
    }

    await prisma.post.delete({ where: { id } });

    res.json({ message: 'Post deleted by admin' });
  } catch (error) {
    console.error('Error deleting post by admin:', error);
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

export default router;
