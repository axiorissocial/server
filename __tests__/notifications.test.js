import { describe, it, expect } from 'vitest';

const createNotification = async (prisma, type, senderId, receiverId, postId, commentId, message) => {
  try {
    if (senderId === receiverId) return 'noop';

    if (type === 'LIKE' && postId) {
      const existing = await prisma.notification.findFirst({ where: { type: 'LIKE', senderId, receiverId, postId } });
      if (existing) return 'noop';
    }

    const created = await prisma.notification.create({ data: { type, senderId, receiverId, postId, commentId, message } });
    return created;
  } catch (e) {
    return null;
  }
};

const createMentionNotifications = async (prisma, content, senderId, postId, commentId) => {
  const mentionRegex = /@(\w+)/g;
  const mentions = [];
  let match;
  while ((match = mentionRegex.exec(content)) !== null) {
    const username = match[1];
    if (!mentions.includes(username)) mentions.push(username);
  }

  const results = [];
  for (const username of mentions) {
    const mentionedUser = await prisma.user.findUnique({ where: { username }, select: { id: true } });
    if (mentionedUser && mentionedUser.id !== senderId) {
      const r = await createNotification(prisma, 'MENTION', senderId, mentionedUser.id, postId, commentId);
      results.push(r);
    }
  }
  return results;
};

describe('notification helpers', () => {
  it('does nothing when sender equals receiver', async () => {
    const prisma = { notification: { findFirst: async () => null, create: async () => ({ id: 'n1' }) } };
    const res = await createNotification(prisma, 'LIKE', 'u1', 'u1', 'p1');
    expect(res).toBe('noop');
  });

  it('dedupes LIKE notifications', async () => {
    const prisma = {
      notification: {
        findFirst: async () => ({ id: 'exists' }),
        create: async () => ({ id: 'should-not' })
      }
    };
    const res = await createNotification(prisma, 'LIKE', 'u1', 'u2', 'p1');
    expect(res).toBe('noop');
  });

  it('creates notification when not duplicate or self', async () => {
    const prisma = {
      notification: { findFirst: async () => null, create: async ({ data }) => ({ id: 'n2', ...data }) }
    };
    const res = await createNotification(prisma, 'COMMENT', 'u1', 'u2', 'p1', null, 'hello');
    expect(res).toHaveProperty('id', 'n2');
    expect(res).toHaveProperty('type', 'COMMENT');
    expect(res).toHaveProperty('receiverId', 'u2');
  });

  it('createMentionNotifications finds mentioned users and creates notifications (excluding sender)', async () => {
    const prisma = {
      user: {
        findUnique: async ({ where }) => {
          if (where.username === 'alice') return { id: 'alice-id' };
          if (where.username === 'bob') return { id: 'bob-id' };
          return null;
        }
      },
      notification: {
        findFirst: async () => null,
        create: async ({ data }) => ({ id: `n-${data.receiverId}`, ...data })
      }
    };

    const res = await createMentionNotifications(prisma, 'Hello @alice and @bob and @alice', 'sender-id', 'post-1');
    expect(Array.isArray(res)).toBe(true);
    expect(res.length).toBe(2);
    expect(res[0]).toHaveProperty('receiverId', 'alice-id');
    expect(res[1]).toHaveProperty('receiverId', 'bob-id');
  });
});
