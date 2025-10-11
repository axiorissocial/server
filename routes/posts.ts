import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import fsExtra, { ensureDir } from 'fs-extra';
import { prisma } from '../index.js';
import { censor, containsProfanityStrict, containsHighSeverity, containsProfanityForPosts } from '../utils/profanity.js';
import { awardXp, revokeXp } from '../utils/leveling.js';
import { addUrl, removeUrl } from '../utils/sitemapCache.js';
import { requireAuth, optionalAuth, AuthenticatedRequest } from '../middleware/auth.js';
import { checkBanned } from '../middleware/checkBanned.js';
import { createNotification, createMentionNotifications } from './notifications.js';
import { VideoProcessor } from '../utils/videoProcessor.js';

const viewCache = new Map<string, number>();

const POST_REACTION_EMOJIS = ['👍', '❤️', '😂', '😮', '🎉'] as const;
type PostReactionEmoji = typeof POST_REACTION_EMOJIS[number];
type ReactionCounts = Partial<Record<PostReactionEmoji, number>>;

const isValidReactionEmoji = (emoji: string): emoji is PostReactionEmoji =>
  POST_REACTION_EMOJIS.includes(emoji as PostReactionEmoji);

type ReactionSummaryItem = {
  emoji: PostReactionEmoji;
  count: number;
  isSelected: boolean;
};

type PostReactionSummary = {
  availableEmojis: readonly PostReactionEmoji[];
  summary: ReactionSummaryItem[];
  totalCount: number;
  currentUserReaction: PostReactionEmoji | null;
};

const buildReactionSummary = (
  counts: ReactionCounts,
  currentUserReaction: PostReactionEmoji | null
): PostReactionSummary => {
  const summary = POST_REACTION_EMOJIS.map(emoji => {
    const count = counts[emoji] ?? 0;
    return {
      emoji,
      count,
      isSelected: currentUserReaction === emoji,
    } satisfies ReactionSummaryItem;
  });

  const totalCount = summary.reduce((acc, item) => acc + item.count, 0);

  return {
    availableEmojis: POST_REACTION_EMOJIS,
    summary,
    totalCount,
    currentUserReaction,
  };
};

const getReactionSummaryForPosts = async (
  postIds: string[],
  userId?: string
): Promise<Map<string, PostReactionSummary>> => {
  if (!postIds.length) {
    return new Map();
  }

  const countsPromise = prisma.postReaction.groupBy({
    by: ['postId', 'emoji'],
    where: { postId: { in: postIds } },
    _count: { _all: true },
  });

  const userReactionsPromise = userId
    ? prisma.postReaction.findMany({
        where: {
          postId: { in: postIds },
          userId,
        },
        select: {
          postId: true,
          emoji: true,
        },
      })
    : Promise.resolve([] as { postId: string; emoji: PostReactionEmoji }[]);

  const [groupedCounts, userReactions] = await Promise.all([countsPromise, userReactionsPromise]);

  const countsByPost = new Map<string, ReactionCounts>();
  for (const item of groupedCounts) {
    const emoji = item.emoji as PostReactionEmoji;
    if (!isValidReactionEmoji(emoji)) continue;

    const countValue = typeof item._count === 'object' && item._count !== null && '_all' in item._count
      ? Number(item._count._all)
      : 0;

    const existing = countsByPost.get(item.postId) ?? {};
    existing[emoji] = countValue;
    countsByPost.set(item.postId, existing);
  }

  const userReactionByPost = new Map<string, PostReactionEmoji | null>();
  if (Array.isArray(userReactions)) {
    for (const reaction of userReactions as { postId: string; emoji: string }[]) {
      if (isValidReactionEmoji(reaction.emoji)) {
        userReactionByPost.set(reaction.postId, reaction.emoji);
      }
    }
  }

  const result = new Map<string, PostReactionSummary>();
  for (const postId of postIds) {
    const counts = countsByPost.get(postId) ?? {};
    const currentUserReaction = userReactionByPost.get(postId) ?? null;
    result.set(postId, buildReactionSummary(counts, currentUserReaction));
  }

  return result;
};

const getReactionSummaryForPost = async (
  postId: string,
  userId?: string
): Promise<PostReactionSummary> => {
  const summaryMap = await getReactionSummaryForPosts([postId], userId);
  return summaryMap.get(postId) ?? buildReactionSummary({}, null);
};

const deleteMediaFiles = (mediaItems: any[]): void => {
  if (!Array.isArray(mediaItems)) return;
  
  mediaItems.forEach(mediaItem => {
    if (mediaItem && mediaItem.url) {
      try {
        const filePath = path.join(process.cwd(), 'public', mediaItem.url);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          console.log(`Deleted media file: ${mediaItem.url}`);
        }
      } catch (error) {
        console.error(`Failed to delete media file ${mediaItem.url}:`, error);
      }
    }
  });
};

const mediaStorage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      const postId = req.body.postId;
      let uploadDir: string;
      
      if (postId) {
        uploadDir = path.join(process.cwd(), 'public', 'uploads', 'media', postId);
      } else {
        uploadDir = path.join(process.cwd(), 'public', 'uploads', 'media');
      }
      
      await ensureDir(uploadDir);
      cb(null, uploadDir);
    } catch (error) {
      cb(error instanceof Error ? error : new Error('Failed to create upload directory'), '');
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `media-${uniqueSuffix}${ext}`);
  }
});

const mediaUpload = multer({
  storage: mediaStorage,
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 5
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
      const allowedImageTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
      const allowedVideoTypes = ['video/mp4', 'video/webm', 'video/mov', 'video/avi'];
      
      if (allowedImageTypes.includes(file.mimetype) || allowedVideoTypes.includes(file.mimetype)) {
        cb(null, true);
      } else {
        cb(new Error('Unsupported file type. Only JPEG, PNG, GIF, WebP images and MP4, WebM, MOV, AVI videos are allowed.'));
      }
    } else {
      cb(new Error('Only image and video files are allowed'));
    }
  }
});

const processCommentsWithLikes = (comments: any[], userId?: string) => {
  return comments.map(comment => {
    const processedComment = {
      ...comment,
      isLiked: userId ? comment.likes.length > 0 : false,
      likesCount: comment._count.likes,
      likes: undefined,
      _count: undefined,
    };
    
    if (comment.replies && comment.replies.length > 0) {
      processedComment.replies = processCommentsWithLikes(comment.replies, userId);
    }
    
    return processedComment;
  });
};

const router = Router();
const HASHTAG_REGEX = /(^|[^A-Za-z0-9_])#([A-Za-z0-9_]{2,50})/g;
const COUNTRY_HEADER_CANDIDATES = ['x-country-code', 'cf-ipcountry', 'x-vercel-ip-country', 'x-country', 'x-geo-country'];
const TRENDING_WINDOW_DAYS = 7;
const DEFAULT_TRENDING_LIMIT = 10;

const extractHashtags = (text: string): string[] => {
  if (!text) {
    return [];
  }

  HASHTAG_REGEX.lastIndex = 0;
  const matches = new Set<string>();
  let match: RegExpExecArray | null;

  while ((match = HASHTAG_REGEX.exec(text)) !== null) {
    const tag = match[2]?.trim();
    if (!tag) {
      continue;
    }

    const normalized = tag.toLowerCase();
    if (normalized.length >= 2 && normalized.length <= 50) {
      matches.add(normalized);
    }
  }

  return Array.from(matches);
};

const extractCountryCodeCandidate = (value: string | string[] | undefined): string | null => {
  if (!value) {
    return null;
  }

  const raw = Array.isArray(value) ? value[0] : value;
  if (!raw) {
    return null;
  }

  const cleaned = raw.split(',')[0]?.split(';')[0]?.trim();
  if (!cleaned) {
    return null;
  }

  if (/^[A-Za-z]{2}$/.test(cleaned)) {
    return cleaned.toUpperCase();
  }

  const parts = cleaned.split(/[-_]/);
  const possible = parts[parts.length - 1];
  if (possible && /^[A-Za-z]{2}$/.test(possible)) {
    return possible.toUpperCase();
  }

  return null;
};

const resolveCountryCode = (req: Request): string | null => {
  for (const header of COUNTRY_HEADER_CANDIDATES) {
    const candidate = extractCountryCodeCandidate(req.headers[header] as string | undefined);
    if (candidate) {
      return candidate;
    }
  }

  const acceptLanguage = req.headers['accept-language'];
  if (typeof acceptLanguage === 'string' && acceptLanguage.length) {
    const primary = acceptLanguage.split(',')[0]?.split(';')[0];
    if (primary) {
      const parts = primary.split(/[-_]/);
      if (parts.length > 1) {
        const potential = parts[parts.length - 1];
        if (/^[A-Za-z]{2}$/.test(potential)) {
          return potential.toUpperCase();
        }
      }
    }
  }

  return null;
};

const syncPostHashtags = async (postId: string, content: string, countryCode: string | null): Promise<string[]> => {
  const tags = extractHashtags(content);

  await prisma.$transaction(async (tx) => {
    await tx.postHashtag.deleteMany({ where: { postId } });

    if (!tags.length) {
      return;
    }

    const hashtagRecords = await Promise.all(
      tags.map(tag =>
        tx.hashtag.upsert({
          where: { tag },
          update: {},
          create: { tag },
        })
      )
    );

    const entries = hashtagRecords.map(record => ({
      postId,
      hashtagId: record.id,
      countryCode: countryCode ?? null,
    }));

    if (entries.length > 0) {
      await tx.postHashtag.createMany({ data: entries });
    }
  });

  return tags;
};

const getTrendingHashtags = async (options: { since: Date; limit: number; countryCode?: string | null }) => {
  const where: any = {
    createdAt: { gte: options.since },
    post: {
      is: {
        isPrivate: false,
      }
    }
  };

  if (options.countryCode) {
    where.countryCode = options.countryCode.toUpperCase();
  }

  const hashtagEntries = await prisma.postHashtag.findMany({
    where,
    select: {
      hashtagId: true,
      createdAt: true,
    }
  });

  if (!hashtagEntries.length) {
    return [] as Array<{
      tag: string;
      usageCount: number;
      rank: number;
      lastUsedAt: Date | null;
      share: number;
    }>;
  }

  const aggregates = new Map<string, { count: number; lastUsed: Date | null }>();

    for (const entry of hashtagEntries) {
    const current = aggregates.get(entry.hashtagId) ?? { count: 0, lastUsed: null };
    const createdAt = entry.createdAt instanceof Date ? entry.createdAt : new Date(entry.createdAt);
    const lastUsed = current.lastUsed && current.lastUsed > createdAt ? current.lastUsed : createdAt;
    aggregates.set(entry.hashtagId, {
      count: current.count + 1,
      lastUsed,
    });
    
  }

  const hashtagIds = Array.from(aggregates.keys());

  const hashtagRecords = await prisma.hashtag.findMany({
    where: {
      id: { in: hashtagIds }
    },
    select: {
      id: true,
      tag: true,
    }
  });

  const hashtagMap = new Map<string, string>(hashtagRecords.map(record => [record.id, record.tag]));
  const overallTotal = Array.from(aggregates.values()).reduce((sum, item) => sum + item.count, 0);

  const unsorted = hashtagIds
    .map((id) => {
      const tag = hashtagMap.get(id);
      if (!tag) {
        return null;
      }

      const aggregate = aggregates.get(id)!;
      return {
        tag,
        usageCount: aggregate.count,
        lastUsedAt: aggregate.lastUsed,
        share: overallTotal > 0 ? aggregate.count / overallTotal : 0,
      };
    })
    .filter((value): value is NonNullable<typeof value> => Boolean(value));

  const sorted = unsorted.sort((a, b) => {
    if (b.usageCount !== a.usageCount) {
      return b.usageCount - a.usageCount;
    }

    if (a.lastUsedAt && b.lastUsedAt) {
      return b.lastUsedAt.getTime() - a.lastUsedAt.getTime();
    }

    if (a.lastUsedAt) {
      return -1;
    }

    if (b.lastUsedAt) {
      return 1;
    }

    return a.tag.localeCompare(b.tag);
  });

  return sorted.slice(0, options.limit).map((item, index) => ({
    ...item,
    rank: index + 1,
  }));
};

router.get('/posts/trending/hashtags', optionalAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const limitParam = parseInt(req.query.limit as string, 10);
    const windowParam = parseInt(req.query.windowDays as string, 10);
    const explicitCountry = typeof req.query.countryCode === 'string' ? req.query.countryCode.trim() : '';

    const limit = Number.isFinite(limitParam) && limitParam > 0
      ? Math.min(limitParam, 25)
      : DEFAULT_TRENDING_LIMIT;

    const windowDays = Number.isFinite(windowParam) && windowParam > 0
      ? Math.min(windowParam, 30)
      : TRENDING_WINDOW_DAYS;

    const since = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1000);

    const resolvedCountryFromHeaders = resolveCountryCode(req);
    const candidateCountry = explicitCountry || resolvedCountryFromHeaders || '';
    const normalizedCountry = /^[A-Za-z]{2}$/.test(candidateCountry)
      ? candidateCountry.toUpperCase()
      : null;

    const [global, local] = await Promise.all([
      getTrendingHashtags({ since, limit }),
      normalizedCountry ? getTrendingHashtags({ since, limit, countryCode: normalizedCountry }) : Promise.resolve([]),
    ]);

    res.json({
      since: since.toISOString(),
      windowDays,
      limit,
      countryCode: normalizedCountry,
      global,
      local,
      localFallbackToGlobal: Boolean(normalizedCountry && local.length === 0 && global.length > 0),
      generatedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Error fetching trending hashtags:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/posts/hashtags/:tag', optionalAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const rawTag = req.params.tag?.toLowerCase() ?? '';
    const normalizedTag = rawTag.replace(/^#/, '').trim();

    if (!normalizedTag || normalizedTag.length < 2) {
      return res.status(400).json({ message: 'Invalid hashtag' });
    }

    const pageParam = parseInt(req.query.page as string, 10);
    const limitParam = parseInt(req.query.limit as string, 10);
    const page = Number.isFinite(pageParam) && pageParam > 0 ? pageParam : 1;
    const limit = Number.isFinite(limitParam) && limitParam > 0 ? Math.min(limitParam, 50) : 20;
    const skip = (page - 1) * limit;

    const where = {
      isPrivate: false,
      hashtags: {
        some: {
          hashtag: {
            tag: normalizedTag,
          }
        }
      }
    };

    const [posts, totalPosts] = await Promise.all([
      prisma.post.findMany({
        where,
        include: {
          user: {
            select: {
              id: true,
              username: true,
              profile: {
                select: {
                  displayName: true,
                  avatar: true,
                  avatarGradient: true,
                  bannerGradient: true,
                }
              }
            }
          },
          likes: {
            select: { userId: true },
          },
          hashtags: {
            include: {
              hashtag: { select: { tag: true } }
            }
          },
          _count: {
            select: {
              likes: true,
              comments: true,
            }
          }
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      prisma.post.count({ where })
    ]);

    const reactionsByPost = await getReactionSummaryForPosts(posts.map(post => post.id), req.userId);

    const formatted = posts.map(post => {
      const { likes, _count, hashtags, ...rest } = post;
      return {
        ...rest,
        hashtags: hashtags.map(entry => entry.hashtag.tag),
        isLiked: req.userId ? likes.some(like => like.userId === req.userId) : false,
        commentsCount: _count?.comments ?? 0,
        reactions: reactionsByPost.get(post.id) ?? buildReactionSummary({}, null),
      };
    });

    const totalPages = Math.ceil(totalPosts / limit);

    res.json({
      tag: normalizedTag,
      posts: formatted,
      pagination: {
        currentPage: page,
        totalPages,
        totalPosts,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1,
      }
    });
  } catch (error) {
    console.error('Error fetching hashtag timeline:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/posts', optionalAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const rawPage = parseInt(req.query.page as string, 10);
    const rawLimit = parseInt(req.query.limit as string, 10);
    const searchTerm = typeof req.query.search === 'string' ? req.query.search.trim() : '';
    const userId = typeof req.query.userId === 'string' ? req.query.userId : undefined;
    const includePrivateRequested = req.query.includePrivate === 'true' || req.query.includePrivate === '1';
    const sortParam = typeof req.query.sort === 'string' ? req.query.sort.toLowerCase() : '';

    const page = Number.isFinite(rawPage) && rawPage > 0 ? rawPage : 1;
    const isDefaultFeed = !searchTerm && !userId;

    let sortMode: 'recent' | 'recommended' | 'trending';
    if (sortParam === 'recent' || sortParam === 'recommended' || sortParam === 'trending') {
      sortMode = sortParam;
    } else {
      sortMode = isDefaultFeed ? 'recommended' : 'recent';
    }

    const limit = Number.isFinite(rawLimit) && rawLimit > 0
      ? Math.min(rawLimit, 100)
      : (isDefaultFeed ? 25 : 10);
    const skip = (page - 1) * limit;

    let includePrivate = false;
    if (includePrivateRequested && req.userId) {
      const requestingUser = await prisma.user.findUnique({ where: { id: req.userId } });
      includePrivate = Boolean(requestingUser?.isAdmin);
    }

    const where: any = {};

    if (!includePrivate) {
      where.isPrivate = false;
    }

    if (userId) {
      where.userId = userId;
    }

    if (searchTerm) {
      where.OR = [
        { id: searchTerm },
  { slug: { contains: searchTerm } },
  { content: { contains: searchTerm } },
  { title: { contains: searchTerm } },
        {
          user: {
            is: {
              username: { contains: searchTerm }
            }
          }
        },
        {
          user: {
            is: {
              id: searchTerm
            }
          }
        }
      ];
    }

    if ((sortMode === 'recommended' || sortMode === 'trending') && isDefaultFeed) {
      const windowDays = sortMode === 'trending' ? 7 : 30;
      const createdAfter = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1000);
      if (where.createdAt) {
        where.createdAt.gte = createdAfter;
      } else {
        where.createdAt = { gte: createdAfter };
      }
    }

    const orderBy = sortMode === 'recent'
      ? [
          { isPinned: 'desc' as const },
          { createdAt: 'desc' as const },
        ]
      : [
          { isPinned: 'desc' as const },
          { likesCount: 'desc' as const },
          { viewsCount: 'desc' as const },
          { updatedAt: 'desc' as const },
          { createdAt: 'desc' as const },
        ];

    const posts = await prisma.post.findMany({
      where,
      include: {
        user: {
          select: {
            id: true,
            username: true,
            profile: {
              select: {
                displayName: true,
                avatar: true,
                avatarGradient: true,
                bannerGradient: true,
              }
            }
          }
        },
        likes: {
          select: {
            userId: true,
          }
        },
        hashtags: {
          include: {
            hashtag: {
              select: {
                tag: true,
              }
            }
          }
        },
        _count: {
          select: {
            likes: true,
            comments: true,
          }
        }
      },
      orderBy,
      skip,
      take: limit,
    });

    const postIds = posts.map(post => post.id);
    const reactionsByPost = await getReactionSummaryForPosts(postIds, req.userId);

    const postsWithLikeStatus = posts.map(post => {
      const { likes, _count, hashtags, ...rest } = post;
      return {
        ...rest,
        hashtags: hashtags.map(entry => entry.hashtag.tag),
        isLiked: req.userId ? likes.some(like => like.userId === req.userId) : false,
        commentsCount: _count?.comments ?? 0,
        reactions: reactionsByPost.get(post.id) ?? buildReactionSummary({}, null),
      };
    });

    const totalPosts = await prisma.post.count({ where });
    const totalPages = Math.ceil(totalPosts / limit);

    res.json({
      posts: postsWithLikeStatus,
      pagination: {
        currentPage: page,
        totalPages,
        totalPosts,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1,
      },
      sort: sortMode,
    });

  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/posts/:id', optionalAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;

    const post = await prisma.post.findFirst({
      where: {
        id,
        isPrivate: false,
      },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            profile: {
              select: {
                displayName: true,
                avatar: true,
                avatarGradient: true,
                bannerGradient: true,
              }
            }
          }
        },
        likes: {
          select: {
            userId: true,
          }
        },
        hashtags: {
          include: {
            hashtag: {
              select: {
                tag: true,
              }
            }
          }
        },
        _count: {
          select: {
            likes: true,
            comments: true,
          }
        }
      },
    });

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const isPostOwner = Boolean(req.userId && req.userId === post.userId);

    if (!isPostOwner) {
      const sessionData = req.session as typeof req.session & { viewedPosts?: Record<string, number> };
      const now = Date.now();
      let viewRecorded = false;

      if (sessionData) {
        if (!sessionData.viewedPosts) {
          sessionData.viewedPosts = {};
        }

        if (!sessionData.viewedPosts[id]) {
          await prisma.post.update({
            where: { id },
            data: { viewsCount: { increment: 1 } }
          });
          sessionData.viewedPosts[id] = now;
          viewRecorded = true;
        } else {
          viewRecorded = true;
        }
      }

      if (!viewRecorded) {
        const userAgent = req.get('User-Agent') || '';
        const clientIP = req.ip || req.connection.remoteAddress || '';
        const sessionId = req.userId ? `user_${req.userId}` : `${clientIP}_${userAgent.slice(0, 50)}`;

        const viewKey = `${sessionId}_${id}`;
        const lastViewTime = viewCache.get(viewKey);

        if (!lastViewTime || (now - lastViewTime) > 30 * 60 * 1000) {
          await prisma.post.update({
            where: { id },
            data: { viewsCount: { increment: 1 } }
          });

          viewCache.set(viewKey, now);

          if (viewCache.size > 10000) {
            const entries = Array.from(viewCache.entries()) as [string, number][];
            entries.sort((a, b) => a[1] - b[1]);
            viewCache.clear();
            entries.slice(-5000).forEach(([key, time]) => {
              viewCache.set(key, time);
            });
          }
        }
      }
    }

    const reactionSummary = await getReactionSummaryForPost(id, req.userId);

    const { likes, _count, hashtags, ...rest } = post;

    const postWithLikeStatus = {
      ...rest,
      hashtags: hashtags.map(entry => entry.hashtag.tag),
      isLiked: req.userId ? likes.some(like => like.userId === req.userId) : false,
      commentsCount: _count?.comments ?? 0,
      reactions: reactionSummary,
    };

    res.json(postWithLikeStatus);

  } catch (error) {
    console.error('Error fetching post:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/posts/media', requireAuth, checkBanned, mediaUpload.array('media', 5), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const files = req.files as Express.Multer.File[];
    const postId = req.body.postId;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }

    const processedMedia: any[] = [];

    for (const file of files) {
      const isVideo = file.mimetype.startsWith('video/');
      let mediaUrl: string;
      let hlsUrl: string | null = null;
      
      if (postId) {
        mediaUrl = `/uploads/media/${postId}/${file.filename}`;
      } else {
        mediaUrl = `/uploads/media/${file.filename}`;
      }
      
      if (isVideo) {
        try {
          const inputPath = file.path;
          const outputDir = path.dirname(inputPath);
          const filename = path.parse(file.filename).name;
          
          const hlsResult = await VideoProcessor.processToHLS(inputPath, outputDir, filename);
          
          if (hlsResult && hlsResult.hlsPath) {
            const relativePath = path.relative(path.join(process.cwd(), 'public'), hlsResult.hlsPath);
            hlsUrl = '/' + relativePath.replace(/\\/g, '/');
          }
        } catch (error) {
          console.error('HLS processing failed for', file.filename, ':', error);
        }
      }

      processedMedia.push({
        url: mediaUrl,
        hlsUrl: hlsUrl,
        type: isVideo ? 'video' : 'image',
        originalName: file.originalname,
        size: file.size
      });
    }

    res.json({
      success: true,
      media: processedMedia
    });

  } catch (error) {
    console.error('Error uploading media:', error);
    res.status(500).json({ error: 'Failed to upload media' });
  }
});

router.post('/posts', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { content, title, isPrivate = false, media } = req.body;
    const userId = req.userId!;
    const resolvedCountryCode = resolveCountryCode(req);

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ message: 'Post content is required' });
    }

    if (containsHighSeverity(content)) {
      return res.status(400).json({ message: 'Post contains disallowed language' });
    }

    if (containsProfanityForPosts(content)) {
      return res.status(400).json({ message: 'Post contains disallowed language' });
    }

    const sanitizedContent = censor(content.trim());

    if (sanitizedContent.length > 1000) {
      return res.status(400).json({ message: 'Post content must be 1000 characters or less' });
    }

    let slug = null;
    if (title) {
      if (containsProfanityForPosts(title) || containsHighSeverity(title)) {
        return res.status(400).json({ message: 'Title contains disallowed language' });
      }
      slug = title
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .substring(0, 50);
      
      const existingPost = await prisma.post.findUnique({ where: { slug } });
      if (existingPost) {
        slug = `${slug}-${Date.now()}`;
      }
    }


    const post = await prisma.post.create({
      data: {
        content: sanitizedContent,
        title: title?.trim() || null,
        slug,
        isPrivate: Boolean(isPrivate),
        media: media || null,
        userId,
        originCountryCode: resolvedCountryCode,
      },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            profile: {
              select: {
                displayName: true,
                avatar: true,
                avatarGradient: true,
                bannerGradient: true,
              }
            }
          }
        },
        _count: {
          select: {
            likes: true,
            comments: true,
          }
        }
      }
    });

  await createMentionNotifications(sanitizedContent, userId, post.id);
  const hashtags = await syncPostHashtags(post.id, sanitizedContent, post.originCountryCode ?? resolvedCountryCode ?? null);

    const { _count, ...postPayload } = post;

    res.status(201).json({
      message: 'Post created successfully',
      post: {
        ...postPayload,
        isLiked: false,
        commentsCount: _count.comments,
        reactions: buildReactionSummary({}, null),
        hashtags,
      }
    });

  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/posts/:id/like', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const userId = req.userId!;

    const post = await prisma.post.findFirst({
      where: {
        id,
        isPrivate: false,
      }
    });

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const existingLike = await prisma.like.findUnique({
      where: {
        userId_postId: {
          userId,
          postId: id,
        }
      }
    });

    if (existingLike) {
      await prisma.$transaction([
        prisma.like.delete({
          where: {
            userId_postId: {
              userId,
              postId: id,
            }
          }
        }),
        prisma.post.update({
          where: { id },
          data: { likesCount: { decrement: 1 } }
        })
      ]);

      try {
        if (post.userId && post.userId !== userId) {
          await revokeXp(post.userId, 2, 'unlike', { sourceType: 'post_like', sourceId: `${id}:${userId}` });
        }
      } catch (err) {
        console.error('Failed to revoke XP on unlike:', err);
      }

      res.json({ message: 'Post unliked', isLiked: false });
    } else {
      await prisma.$transaction([
        prisma.like.create({
          data: {
            userId,
            postId: id,
          }
        }),
        prisma.post.update({
          where: { id },
          data: { likesCount: { increment: 1 } }
        })
      ]);

      try {
        if (post.userId && post.userId !== userId) {
          await awardXp(post.userId, 2, 'like_received', { sourceType: 'post_like', sourceId: `${id}:${userId}` });
        }
      } catch (err) {
        console.error('Failed to award XP on like:', err);
      }

      if (post.userId !== userId) {
        await createNotification(
          'LIKE',
          userId,
          post.userId,
          id
        );
      }

      res.json({ message: 'Post liked', isLiked: true });
    }

  } catch (error) {
    console.error('Error toggling like:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/posts/:id/reactions', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const userId = req.userId!;
    const emojiInput = typeof req.body?.emoji === 'string' ? req.body.emoji : '';
    const emoji = emojiInput.trim();

    if (!isValidReactionEmoji(emoji)) {
      return res.status(400).json({ message: 'Invalid reaction emoji' });
    }

    const post = await prisma.post.findFirst({
      where: {
        id,
        isPrivate: false,
      }
    });

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const existingReaction = await prisma.postReaction.findUnique({
      where: {
        postId_userId: {
          postId: id,
          userId,
        }
      }
    });

    let action: 'added' | 'removed' | 'changed' = 'added';

    if (existingReaction) {
      if (existingReaction.emoji === emoji) {
        await prisma.postReaction.delete({
          where: {
            id: existingReaction.id,
          }
        });
        action = 'removed';
      } else {
        await prisma.postReaction.update({
          where: {
            id: existingReaction.id,
          },
          data: {
            emoji,
          }
        });
        action = 'changed';
      }
    } else {
      await prisma.postReaction.create({
        data: {
          postId: id,
          userId,
          emoji,
        }
      });
    }

    const reactions = await getReactionSummaryForPost(id, userId);

    res.json({
      message:
        action === 'added'
          ? 'Reaction added'
          : action === 'changed'
            ? 'Reaction updated'
            : 'Reaction removed',
      action,
      reactions,
    });
  } catch (error) {
    console.error('Error updating reaction:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.delete('/posts/:id/reactions', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const userId = req.userId!;

    const existingReaction = await prisma.postReaction.findUnique({
      where: {
        postId_userId: {
          postId: id,
          userId,
        }
      }
    });

    if (existingReaction) {
      await prisma.postReaction.delete({
        where: {
          id: existingReaction.id,
        }
      });
    }

    const reactions = await getReactionSummaryForPost(id, userId);

    res.json({
      message: existingReaction ? 'Reaction removed' : 'No reaction to remove',
      reactions,
    });
  } catch (error) {
    console.error('Error removing reaction:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/users/search', async (req: Request, res: Response) => {
  try {
    const query = req.query.q as string;
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const currentUserId = req.session?.userId;

    if (!query) {
      return res.status(400).json({ message: 'Search query is required' });
    }

    const skip = (page - 1) * limit;

    const users = await prisma.user.findMany({
      where: {
        OR: [
          { username: { contains: query } },
          { profile: { displayName: { contains: query } } },
        ]
      },
      select: {
        id: true,
        username: true,
        bio: true,
        isVerified: true,
        isAdmin: true,
        profile: {
          select: {
            displayName: true,
            avatar: true,
            avatarGradient: true,
            bannerGradient: true,
          }
        },
        _count: {
          select: {
            posts: true,
            followers: true,
          }
        },
        followers: currentUserId ? {
          where: {
            followerId: currentUserId
          },
          select: {
            id: true
          }
        } : false
      },
      skip,
      take: limit,
      orderBy: {
        username: 'asc',
      }
    });

    const usersWithFollowStatus = users.map(user => ({
      ...user,
      isFollowing: currentUserId ? user.followers.length > 0 : false,
      followers: undefined
    }));

    const totalUsers = await prisma.user.count({
      where: {
        OR: [
          { username: { contains: query } },
          { profile: { displayName: { contains: query } } },
        ]
      }
    });

    const totalPages = Math.ceil(totalUsers / limit);

    res.json({
      users: usersWithFollowStatus,
      pagination: {
        currentPage: page,
        totalPages,
        totalUsers,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1,
      }
    });

  } catch (error) {
    console.error('Error searching users:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.put('/posts/:id', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const postId = req.params.id;
    const userId = req.session!.userId!;
    const { title, content, media } = req.body;
    const resolvedCountryCode = resolveCountryCode(req);

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Content is required' });
    }

    if (content.length > 10000) {
      return res.status(400).json({ error: 'Content is too long (max 10,000 characters)' });
    }

    if (title && title.length > 200) {
      return res.status(400).json({ error: 'Title is too long (max 200 characters)' });
    }

    const existingPost = await prisma.post.findUnique({
      where: { id: postId },
      include: { user: true }
    });

    if (!existingPost) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (existingPost.userId !== userId) {
      return res.status(403).json({ error: 'You can only edit your own posts' });
    }

    if (media !== undefined && existingPost.media) {
      try {
        const oldMedia = existingPost.media as any;
        deleteMediaFiles(oldMedia);
      } catch (error) {
        console.error('Error deleting old media files:', error);
      }
    }

    const nextCountryCode = existingPost.originCountryCode ?? resolvedCountryCode ?? null;

    if (containsHighSeverity(content) || containsProfanityForPosts(content)) {
      return res.status(400).json({ error: 'Post contains disallowed language' });
    }

    if (title && (containsProfanityForPosts(title) || containsHighSeverity(title))) {
      return res.status(400).json({ error: 'Title contains disallowed language' });
    }

    const updatedPost = await prisma.post.update({
      where: { id: postId },
      data: {
        title: title || null,
        content: content.trim(),
        media: media !== undefined ? media : undefined,
        updatedAt: new Date(),
        originCountryCode: nextCountryCode,
      },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            profile: {
              select: {
                displayName: true,
                avatar: true,
                avatarGradient: true,
                bannerGradient: true,
              }
            }
          }
        },
        likes: {
          select: { userId: true },
          where: { userId }
        },
        _count: {
          select: {
            likes: true,
            comments: true,
          }
        }
      }
    });

    const hashtags = await syncPostHashtags(postId, updatedPost.content, nextCountryCode);

    const { likes, _count, ...rest } = updatedPost;

    const response = {
      ...rest,
      isLiked: likes.length > 0,
      likesCount: _count.likes,
      commentsCount: _count.comments,
      hashtags,
    };

    res.json(response);

  } catch (error) {
    console.error('Error updating post:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/posts/:id', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const postId = req.params.id;
    const userId = req.session!.userId!;

    const existingPost = await prisma.post.findUnique({
      where: { id: postId },
      include: { user: true }
    });

    if (!existingPost) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (existingPost.userId !== userId) {
      return res.status(403).json({ error: 'You can only delete your own posts' });
    }

    if (existingPost.media) {
      try {
        const mediaItems = existingPost.media as any;
        deleteMediaFiles(mediaItems);
      } catch (mediaError) {
        console.error('Error deleting media files:', mediaError);
      }
    }

    await deletePostMediaFiles(postId);

    await prisma.like.deleteMany({
      where: { postId }
    });

    await prisma.post.delete({
      where: { id: postId }
    });

    try {
      const base = (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
      removeUrl(`${base}/post/${encodeURIComponent(postId)}`);
      if (existingPost.slug) {
        removeUrl(`${base}/post/${encodeURIComponent(existingPost.slug)}`);
      }
    } catch (err) {
      console.error('Failed to update sitemap cache after post delete:', err);
    }

    res.json({ message: 'Post deleted successfully' });

  } catch (error) {
    console.error('Error deleting post:', error);
    
    if (error instanceof Error) {
      if (error.message.includes('Foreign key constraint')) {
        return res.status(400).json({ 
          error: 'Cannot delete post: it has associated data that prevents deletion',
          details: 'Please try again or contact support if this issue persists'
        });
      }
    }
    
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/posts/cleanup-media', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    
    const mediaDir = path.join(process.cwd(), 'public', 'uploads', 'media');
    
    if (!fs.existsSync(mediaDir)) {
      return res.json({ message: 'Media directory does not exist', deleted: 0 });
    }

    const files = fs.readdirSync(mediaDir);
    
    const posts = await prisma.post.findMany({
      select: { media: true }
    });
    
    const usedFiles = new Set<string>();
    posts.forEach(post => {
      if (post.media && Array.isArray(post.media)) {
        (post.media as any[]).forEach(mediaItem => {
          if (mediaItem.url) {
            const filename = path.basename(mediaItem.url);
            usedFiles.add(filename);
          }
        });
      }
    });
    
    let deletedCount = 0;
    files.forEach(filename => {
      if (!usedFiles.has(filename) && filename.startsWith('media-')) {
        const filePath = path.join(mediaDir, filename);
        try {
          fs.unlinkSync(filePath);
          deletedCount++;
          console.log(`Cleaned up orphaned media file: ${filename}`);
        } catch (error) {
          console.error(`Failed to delete orphaned media file ${filename}:`, error);
        }
      }
    });
    
    res.json({ 
      message: `Media cleanup completed`, 
      deleted: deletedCount,
      total: files.length,
      remaining: files.length - deletedCount
    });

  } catch (error) {
    console.error('Error during media cleanup:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/posts/:id/comments', optionalAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const postId = req.params.id;
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip = (page - 1) * limit;

    const post = await prisma.post.findUnique({
      where: { id: postId }
    });

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const comments = await prisma.comment.findMany({
      where: { 
        postId,
        parentId: null
      },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            profile: {
              select: {
                displayName: true,
                avatar: true,
                avatarGradient: true,
                bannerGradient: true,
              }
            }
          }
        },
        likes: req.userId ? {
          where: { userId: req.userId }
        } : false,
        _count: {
          select: {
            likes: true
          }
        },
        replies: {
          include: {
            user: {
              select: {
                id: true,
                username: true,
                profile: {
                  select: {
                    displayName: true,
                    avatar: true,
                    avatarGradient: true,
                    bannerGradient: true,
                  }
                }
              }
            },
            likes: req.userId ? {
              where: { userId: req.userId }
            } : false,
            _count: {
              select: {
                likes: true
              }
            },
            replies: {
              include: {
                user: {
                  select: {
                    id: true,
                    username: true,
                    profile: {
                      select: {
                        displayName: true,
                        avatar: true,
                        avatarGradient: true,
                        bannerGradient: true,
                      }
                    }
                  }
                },
                likes: req.userId ? {
                  where: { userId: req.userId }
                } : false,
                _count: {
                  select: {
                    likes: true
                  }
                }
              },
              orderBy: { createdAt: 'asc' }
            }
          },
          orderBy: { createdAt: 'asc' }
        }
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit
    });

    const totalComments = await prisma.comment.count({
      where: { 
        postId,
        parentId: null
      }
    });

    const totalPages = Math.ceil(totalComments / limit);

    const processedComments = processCommentsWithLikes(comments, req.userId);

    res.json({
      comments: processedComments,
      pagination: {
        currentPage: page,
        totalPages,
        totalComments,
        hasNextPage: page < totalPages,
        hasPreviousPage: page > 1,
      }
    });

  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/posts/:id/comments', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const postId = req.params.id;
    const userId = req.session!.userId!;
    const { content, parentId } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Comment content is required' });
    }

    if (containsHighSeverity(content)) {
      return res.status(400).json({ error: 'Comment contains disallowed language' });
    }

    if (content.length > 1000) {
      return res.status(400).json({ error: 'Comment is too long (max 1,000 characters)' });
    }

    const post = await prisma.post.findUnique({
      where: { id: postId }
    });

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (parentId) {
      const parentComment = await prisma.comment.findUnique({
        where: { id: parentId }
      });

      if (!parentComment) {
        return res.status(404).json({ error: 'Parent comment not found' });
      }

      if (parentComment.postId !== postId) {
        return res.status(400).json({ error: 'Parent comment does not belong to this post' });
      }
    }

  const sanitized = censor(content.trim());

    const comment = await prisma.comment.create({
      data: {
        content: sanitized,
        postId,
        userId,
        parentId: parentId || null,
      },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            profile: {
              select: {
                displayName: true,
                avatar: true,
                avatarGradient: true,
                bannerGradient: true,
              }
            }
          }
        }
      }
    });

  await createMentionNotifications(sanitized, userId, postId, comment.id);

    if (parentId) {
      const parentComment = await prisma.comment.findUnique({
        where: { id: parentId },
        select: { userId: true }
      });
      
      if (parentComment && parentComment.userId !== userId) {
        await createNotification(
          'REPLY',
          userId,
          parentComment.userId,
          postId,
          comment.id
        );
      }
    } else {
      if (post.userId !== userId) {
        await createNotification(
          'COMMENT',
          userId,
          post.userId,
          postId,
          comment.id
        );
      }
    }

    res.status(201).json(comment);

  } catch (error) {
    console.error('Error creating comment:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/posts/:id/like', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const postId = req.params.id;
    const userId = req.session!.userId;

    const post = await prisma.post.findUnique({
      where: { id: postId }
    });

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    await prisma.like.deleteMany({
      where: {
        postId,
        userId,
      }
    });

    const likesCount = await prisma.like.count({
      where: { postId }
    });

    res.json({ 
      message: 'Post unliked successfully',
      likesCount,
      isLiked: false
    });

  } catch (error) {
    console.error('Error unliking post:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/comments/:id/like', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const commentId = req.params.id;
    const userId = req.session!.userId!;

    const comment = await prisma.comment.findUnique({
      where: { id: commentId }
    });

    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    const existingLike = await prisma.commentLike.findUnique({
      where: {
        userId_commentId: {
          userId,
          commentId
        }
      }
    });

    if (existingLike) {
      await prisma.commentLike.delete({
        where: {
          userId_commentId: {
            userId,
            commentId
          }
        }
      });

      await prisma.comment.update({
        where: { id: commentId },
        data: { likesCount: { decrement: 1 } }
      });

      res.json({ 
        message: 'Comment unliked successfully',
        isLiked: false
      });
    } else {
      await prisma.commentLike.create({
        data: {
          userId,
          commentId
        }
      });

      await prisma.comment.update({
        where: { id: commentId },
        data: { likesCount: { increment: 1 } }
      });

      if (comment.userId !== userId) {
        await createNotification(
          'COMMENT_LIKE',
          userId,
          comment.userId,
          comment.postId,
          commentId
        );
      }

      res.json({ 
        message: 'Comment liked successfully',
        isLiked: true
      });
    }

  } catch (error) {
    console.error('Error toggling comment like:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/comments/:id', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const commentId = req.params.id;
    const userId = req.user!.id;
    const { content } = req.body;

    if (!content || !content.trim()) {
      return res.status(400).json({ error: 'Comment content is required' });
    }

    if (containsHighSeverity(content)) {
      return res.status(400).json({ error: 'Comment contains disallowed language' });
    }

    if (content.length > 1000) {
      return res.status(400).json({ error: 'Comment is too long. Maximum 1000 characters allowed.' });
    }

    const existingComment = await prisma.comment.findUnique({
      where: { id: commentId },
      select: { userId: true, content: true }
    });

    if (!existingComment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    if (existingComment.userId !== userId) {
      return res.status(403).json({ error: 'You can only edit your own comments' });
    }

    if (existingComment.content === content.trim()) {
      return res.status(400).json({ error: 'No changes detected' });
    }

  const sanitizedUpdate = censor(content.trim());

    const updatedComment = await prisma.comment.update({
      where: { id: commentId },
      data: {
        content: sanitizedUpdate,
        editedAt: new Date()
      },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            profile: {
              select: {
                displayName: true,
                avatar: true,
                avatarGradient: true,
                bannerGradient: true
              }
            }
          }
        },
        _count: {
          select: {
            likes: true,
            replies: true
          }
        },
        likes: userId ? {
          where: { userId },
          take: 1
        } : false
      }
    });

    if (content.includes('@')) {
      await createMentionNotifications(sanitizedUpdate, userId, updatedComment.postId, updatedComment.id);
    }

    const response = {
      ...updatedComment,
      isLiked: userId ? updatedComment.likes.length > 0 : false,
      likesCount: updatedComment._count.likes,
      repliesCount: updatedComment._count.replies
    };

    delete (response as any)._count;
    delete (response as any).likes;

    res.json(response);

  } catch (error) {
    console.error('Error editing comment:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/comments/:id', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const commentId = req.params.id;
    const userId = req.user!.id;

    const comment = await prisma.comment.findUnique({
      where: { id: commentId },
      select: { userId: true, postId: true }
    });

    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    if (comment.userId !== userId) {
      return res.status(403).json({ error: 'You can only delete your own comments' });
    }

    await prisma.comment.delete({
      where: { id: commentId }
    });

    res.json({ message: 'Comment deleted successfully' });

  } catch (error) {
    console.error('Error deleting comment:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/posts/:postId/media/:mediaIndex/download', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { postId, mediaIndex } = req.params;
    const index = Number(mediaIndex);

    if (!Number.isInteger(index) || index < 0) {
      return res.status(400).json({ error: 'Invalid media index' });
    }

    const user = await prisma.user.findUnique({
      where: { id: req.userId }
    });

    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const post = await prisma.post.findUnique({
      where: { id: postId },
      select: { media: true }
    });

    if (!post || !Array.isArray(post.media)) {
      return res.status(404).json({ error: 'Post media not found' });
    }

    const mediaItems = post.media as Array<any>;

    if (index >= mediaItems.length) {
      return res.status(404).json({ error: 'Media item not found' });
    }

    const mediaItem = mediaItems[index];
    if (!mediaItem || typeof mediaItem !== 'object') {
      return res.status(404).json({ error: 'Media item not found' });
    }

    const publicRoot = path.join(process.cwd(), 'public');
    const resolvePublicPath = (relativePath: string | null | undefined) => {
      if (!relativePath) return null;
      const sanitized = relativePath.replace(/^[/\\]+/, '');
      const fullPath = path.join(publicRoot, sanitized);
      const relative = path.relative(publicRoot, fullPath);

      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        return null;
      }

      return fullPath;
    };

    const sendFile = async (filePath: string, downloadName?: string) => {
      const exists = await fsExtra.pathExists(filePath);
      if (!exists) {
        res.status(404).json({ error: 'Media file not found' });
        return;
      }

      const resolvedName = downloadName ?? path.basename(filePath);

      res.download(filePath, resolvedName, (err) => {
        if (err) {
          console.error('Download error:', err);
        }
      });
    };

    if (mediaItem.type === 'image') {
      const originalPath = resolvePublicPath(mediaItem.url);
      if (!originalPath) {
        return res.status(400).json({ error: 'Invalid media path' });
      }

  const downloadName = mediaItem.originalName || path.basename(originalPath);
  await sendFile(originalPath, downloadName);
  return;
    }

    if (mediaItem.type === 'video') {
      const tempDir = path.join(process.cwd(), 'temp');
      await fsExtra.ensureDir(tempDir);

      const baseName = mediaItem.originalName
        ? path.parse(mediaItem.originalName).name
        : path.parse(mediaItem.url || 'video').name || 'video';
      const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e6)}`;
      const downloadName = `${baseName || 'video'}-${uniqueSuffix}.mp4`;
      const tempOutputPath = path.join(tempDir, downloadName);

      try {
        const hlsPath = resolvePublicPath(mediaItem.hlsUrl);
        if (hlsPath) {
          await VideoProcessor.convertHLSToMP4(hlsPath, tempOutputPath);
        } else {
          const originalPath = resolvePublicPath(mediaItem.url);
          if (!originalPath) {
            return res.status(400).json({ error: 'Invalid media path' });
          }

          if (path.extname(originalPath).toLowerCase() === '.mp4') {
            await sendFile(originalPath, mediaItem.originalName || path.basename(originalPath));
            return;
          }

          await VideoProcessor.transcodeToMP4(originalPath, tempOutputPath);
        }

        const finalizedName = mediaItem.originalName
          ? `${path.parse(mediaItem.originalName).name}.mp4`
          : `${baseName || 'video'}.mp4`;

        res.download(tempOutputPath, finalizedName, (err) => {
          if (err) {
            console.error('Download error:', err);
          }
          fsExtra.remove(tempOutputPath).catch(() => undefined);
        });
      } catch (error) {
        await fsExtra.remove(tempOutputPath).catch(() => undefined);
        console.error('Video download preparation failed:', error);
        return res.status(500).json({ error: 'Failed to prepare video download' });
      }

      return;
    }

    return res.status(400).json({ error: 'Unsupported media type' });
  } catch (error) {
    console.error('Error preparing media download:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const deletePostMediaFiles = async (postId: string): Promise<void> => {
  try {
    const SAFE_ID_REGEX = /^[a-zA-Z0-9_-]+$/;
    if (!SAFE_ID_REGEX.test(postId)) {
      throw new Error(`Invalid postId format: ${postId}`);
    }
    const mediaDir = path.join(process.cwd(), 'public', 'uploads', 'media', postId);
    
    if (fs.existsSync(mediaDir)) {
      await VideoProcessor.cleanupVideoFiles(mediaDir);
      
      fs.rmSync(mediaDir, { recursive: true, force: true });
      console.log(`Deleted media directory for post: ${postId}`);
    }
  } catch (error) {
    console.error('Failed to delete media files for post:', postId, error);
  }
};

export default router;