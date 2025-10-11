import { describe, it, expect } from 'vitest';

const mapReasonToEnum = (r) => {
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
      if (typeof r === 'string' && ['SPAM','HARASSMENT','INAPPROPRIATE_CONTENT','COPYRIGHT_VIOLATION','MISINFORMATION','HATE_SPEECH','VIOLENCE','OTHER'].includes(r.toUpperCase())) {
        return r.toUpperCase();
      }
      return 'OTHER';
  }
};

const createReport = async ({ prisma, reporterId, postId, commentId, reason, description }) => {
  if (!reason) throw new Error('Reason is required');
  if (!postId && !commentId) throw new Error('Must specify either postId or commentId');
  if (postId && commentId) throw new Error('Cannot specify both postId and commentId');

  if (postId) {
    const post = await prisma.post.findUnique({ where: { id: postId } });
    if (!post) throw new Error('Post not found');
  }

  if (commentId) {
    const comment = await prisma.comment.findUnique({ where: { id: commentId } });
    if (!comment) throw new Error('Comment not found');
  }

  const existing = await prisma.report.findFirst({ where: { reporterId, ...(postId ? { postId } : { commentId }) } });
  if (existing) throw new Error('You have already reported this item');

  const reasonEnum = mapReasonToEnum(reason);
  const createData = { reporterId, postId, commentId, reason: reasonEnum, description: description ?? null };
  const report = await prisma.report.create({ data: createData });
  return report;
};

describe('reportHelpers (JS)', () => {
  it('mapReasonToEnum works and createReport validations', async () => {
    expect(mapReasonToEnum('spam')).toBe('SPAM');
    expect(mapReasonToEnum('harassment')).toBe('HARASSMENT');
    expect(mapReasonToEnum('sexual')).toBe('INAPPROPRIATE_CONTENT');

    const prismaMock = {
      post: { findUnique: async ({ where }) => ({ id: where.id }) },
      comment: { findUnique: async () => null },
      report: {
        findFirst: async () => null,
        create: async ({ data }) => ({ id: 'r1', ...data })
      }
    };

    await expect(createReport({ prisma: {}, reporterId: 'u1', reason: null })).rejects.toThrow();
    await expect(createReport({ prisma: prismaMock, reporterId: 'u1', reason: 'spam' })).rejects.toThrow();

    const result = await createReport({ prisma: prismaMock, reporterId: 'u1', postId: 'p1', reason: 'spam', description: 'test' });
    expect(result).toHaveProperty('id', 'r1');
    expect(result).toHaveProperty('reporterId', 'u1');
    expect(result).toHaveProperty('reason', 'SPAM');
  });

  it('mapReasonToEnum handles uppercase and enum-like inputs and unknowns', () => {
    expect(mapReasonToEnum('SPAM')).toBe('SPAM');
    expect(mapReasonToEnum('Hate_Speech')).toBe('HATE_SPEECH');
    expect(mapReasonToEnum('unknown_reason')).toBe('OTHER');
    expect(mapReasonToEnum(undefined)).toBe('OTHER');
  });

  it('createReport errors: missing target or both targets', async () => {
    const prismaDummy = { post: { findUnique: async () => null }, comment: { findUnique: async () => null }, report: { findFirst: async () => null } };
    await expect(createReport({ prisma: prismaDummy, reporterId: 'u1', reason: 'spam' })).rejects.toThrow(/Must specify either postId or commentId/);
    await expect(createReport({ prisma: prismaDummy, reporterId: 'u1', postId: 'p1', commentId: 'c1', reason: 'spam' })).rejects.toThrow(/Cannot specify both postId and commentId/);
  });

  it('createReport errors when post/comment not found', async () => {
    const prismaPostMissing = {
      post: { findUnique: async () => null },
      comment: { findUnique: async () => null },
      report: { findFirst: async () => null }
    };
    await expect(createReport({ prisma: prismaPostMissing, reporterId: 'u1', postId: 'missing', reason: 'spam' })).rejects.toThrow(/Post not found/);

    const prismaCommentMissing = {
      post: { findUnique: async () => null },
      comment: { findUnique: async () => null },
      report: { findFirst: async () => null }
    };
    await expect(createReport({ prisma: prismaCommentMissing, reporterId: 'u1', commentId: 'missing', reason: 'spam' })).rejects.toThrow(/Comment not found/);
  });

  it('createReport errors when already reported', async () => {
    const prismaAlready = {
      post: { findUnique: async ({ where }) => ({ id: where.id }) },
      comment: { findUnique: async () => null },
      report: { findFirst: async () => ({ id: 'exists' }) }
    };
    await expect(createReport({ prisma: prismaAlready, reporterId: 'u1', postId: 'p1', reason: 'spam' })).rejects.toThrow(/already reported/);
  });

  it('createReport can create a comment report successfully', async () => {
    const prismaMockComment = {
      post: { findUnique: async () => null },
      comment: { findUnique: async ({ where }) => ({ id: where.id }) },
      report: {
        findFirst: async () => null,
        create: async ({ data }) => ({ id: 'r2', ...data })
      }
    };
    const res = await createReport({ prisma: prismaMockComment, reporterId: 'u2', commentId: 'c42', reason: 'abuse' });
    expect(res).toHaveProperty('id', 'r2');
    expect(res).toHaveProperty('commentId', 'c42');
    expect(res).toHaveProperty('reason', 'HARASSMENT');
  });
});
