import { Router, Response } from 'express';
import { prisma } from '../index.js';
import { mapReasonToEnum, createReport } from '../utils/reportHelpers';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth.js';
import { awardXp } from '../utils/leveling.js';

const router = Router();

router.post('/reports', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { itemType, postId, commentId, reason, description, notes } = req.body;
    const reporterId = req.userId!;

    const descriptionValue: string | undefined = description ?? notes ?? undefined;

    const mapReasonToEnum = (r: unknown): string => {
      if (!r || typeof r !== 'string') return 'OTHER';
      const normalized = r.trim().toLowerCase();
      switch (normalized) {
        case 'spam':
          return 'SPAM';
        case 'harassment':
        case 'abuse':
          return 'HARASSMENT';
        case 'sexual':
        case 'inappropriate':
          return 'INAPPROPRIATE_CONTENT';
        case 'copyright':
        case 'copyright_violation':
          return 'COPYRIGHT_VIOLATION';
        case 'misinformation':
          return 'MISINFORMATION';
        case 'hate':
        case 'hate_speech':
          return 'HATE_SPEECH';
        case 'violence':
          return 'VIOLENCE';
        case 'other':
          return 'OTHER';
        default:
          if (["SPAM","HARASSMENT","INAPPROPRIATE_CONTENT","COPYRIGHT_VIOLATION","MISINFORMATION","HATE_SPEECH","VIOLENCE","OTHER"].includes((r as string).toUpperCase())) {
            return (r as string).toUpperCase();
          }
          return 'OTHER';
      }
    };

    if (!reason) {
      return res.status(400).json({ error: 'Reason is required' });
    }

    if (!postId && !commentId) {
      return res.status(400).json({ error: 'Must specify either postId or commentId' });
    }

    if (postId && commentId) {
      return res.status(400).json({ error: 'Cannot specify both postId and commentId' });
    }

    if (postId) {
      const post = await prisma.post.findUnique({
        where: { id: postId }
      });
      
      if (!post) {
        return res.status(404).json({ error: 'Post not found' });
      }
    }

    if (commentId) {
      const comment = await prisma.comment.findUnique({
        where: { id: commentId }
      });
      
      if (!comment) {
        return res.status(404).json({ error: 'Comment not found' });
      }
    }

    const existingReport = await prisma.report.findFirst({
      where: {
        reporterId,
        ...(postId ? { postId } : { commentId })
      }
    });

    if (existingReport) {
      return res.status(400).json({ error: 'You have already reported this item' });
    }

    const report = await createReport({
      prisma,
      reporterId,
      postId,
      commentId,
      reason,
      description: descriptionValue
    });

    const full = await prisma.report.findUnique({ where: { id: report.id } });

    res.json({
      success: true,
      report: {
        id: full?.id ?? report.id,
        reason: full?.reason ?? report.reason,
        description: full?.description ?? report.description,
        status: full?.status ?? report.status,
        createdAt: full?.createdAt ?? report.createdAt
      }
    });

  } catch (error) {
    console.error('Error creating report:', error);
    res.status(500).json({ error: 'Failed to create report' });
  }
});

router.get('/reports', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId }
    });

    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const allowedPageSizes = [10, 50, 100];
    const status = typeof req.query.status === 'string' ? req.query.status : 'all';
    const rawPage = parseInt(req.query.page as string, 10);
    const rawLimit = parseInt(req.query.limit as string, 10);
    const searchTerm = typeof req.query.search === 'string' ? req.query.search.trim() : '';
    const reportScope = typeof req.query.reportType === 'string' ? req.query.reportType.toLowerCase() : 'all';
    const reasonFilter = typeof req.query.reason === 'string' ? req.query.reason.toUpperCase() : undefined;

    const page = Number.isFinite(rawPage) && rawPage > 0 ? rawPage : 1;
    const limit = allowedPageSizes.includes(rawLimit) ? rawLimit : allowedPageSizes[0];
    const offset = (page - 1) * limit;

    const where: any = {};

    if (status && status !== 'all') {
      where.status = status;
    }

    if (reasonFilter && reasonFilter !== 'ALL') {
      where.reason = reasonFilter;
    }

    if (reportScope === 'post') {
      where.postId = { not: null };
    } else if (reportScope === 'comment') {
      where.commentId = { not: null };
    }

    if (searchTerm) {
      const searchFilter = {
        OR: [
          { id: searchTerm },
          { reason: { contains: searchTerm } },
          { description: { contains: searchTerm } },
          { reporter: { username: { contains: searchTerm } } },
          { post: { id: searchTerm } },
          { post: { title: { contains: searchTerm } } },
          { post: { content: { contains: searchTerm } } },
          { post: { user: { username: { contains: searchTerm } } } },
          { comment: { id: searchTerm } },
          { comment: { content: { contains: searchTerm } } },
          { comment: { user: { username: { contains: searchTerm } } } }
        ]
      };

      if (where.AND) {
        where.AND.push(searchFilter);
      } else {
        where.AND = [searchFilter];
      }
    }

    const [reports, total] = await Promise.all([
      prisma.report.findMany({
        where,
        include: {
          reporter: {
            select: {
              id: true,
              username: true
            }
          },
          post: {
            select: {
              id: true,
              content: true,
              user: {
                select: {
                  id: true,
                  username: true
                }
              }
            }
          },
          comment: {
            select: {
              id: true,
              content: true,
              user: {
                select: {
                  id: true,
                  username: true
                }
              }
            }
          }
        },
        orderBy: {
          createdAt: 'desc'
        },
        skip: offset,
        take: Number(limit)
      }),
      prisma.report.count({ where })
    ]);

    res.json({
      reports,
      pagination: {
        page,
        limit,
        total,
        pages: Math.max(1, Math.ceil(total / limit))
      }
    });

  } catch (error) {
    console.error('Error fetching reports:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

router.patch('/reports/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const { status, reviewNotes } = req.body;

    const user = await prisma.user.findUnique({
      where: { id: req.userId }
    });

    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    if (!['PENDING', 'UNDER_REVIEW', 'RESOLVED', 'DISMISSED'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const report = await prisma.report.update({
      where: { id },
      data: {
        status,
        reviewNotes,
        reviewedAt: new Date(),
        reviewedById: req.userId
      },
      include: {
        reporter: {
          select: {
            id: true,
            username: true
          }
        }
      }
    });

    try {
      if (status === 'RESOLVED' && ['BUG', 'FEATURE_REQUEST'].includes((report.reason ?? '').toUpperCase())) {
        await awardXp(report.reporter.id, 50, 'report_validated', { sourceType: 'report', sourceId: report.id });

        if (report.postId) {
          const post = await prisma.post.findUnique({ where: { id: report.postId } });
          if (!post) {
            await awardXp(report.reporter.id, 25, 'report_resulted_in_deletion', { sourceType: 'report_deletion', sourceId: report.id });
          }
        }
      }
    } catch (err) {
      console.error('Failed to award XP for report resolution:', err);
    }

    res.json({ report });

  } catch (error) {
    console.error('Error updating report:', error);
    res.status(500).json({ error: 'Failed to update report' });
  }
});

router.get('/reports/stats', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId }
    });

    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const [
      totalReports,
      pendingReports,
      resolvedReports,
      dismissedReports,
      postReports,
      commentReports,
      reportsByReason
    ] = await Promise.all([
      prisma.report.count(),
      prisma.report.count({ where: { status: 'PENDING' } }),
      prisma.report.count({ where: { status: 'RESOLVED' } }),
      prisma.report.count({ where: { status: 'DISMISSED' } }),
      prisma.report.count({ where: { postId: { not: null } } }),
      prisma.report.count({ where: { commentId: { not: null } } }),
      prisma.report.groupBy({
        by: ['reason'],
        _count: { id: true }
      })
    ]);

    res.json({
      stats: {
        total: totalReports,
        pending: pendingReports,
        resolved: resolvedReports,
        dismissed: dismissedReports,
        byType: {
          posts: postReports,
          comments: commentReports
        },
        byReason: reportsByReason.reduce((acc, item) => {
          acc[item.reason] = item._count?.id || 0;
          return acc;
        }, {} as Record<string, number>)
      }
    });

  } catch (error) {
    console.error('Error fetching report stats:', error);
    res.status(500).json({ error: 'Failed to fetch report statistics' });
  }
});

export default router;