import { prisma } from '../index.js';

export const computeLevelFromXp = (xp: number): number => {
  if (xp <= 0) return 1;
  return Math.max(1, Math.floor(0.1 * Math.sqrt(xp)) + 1);
};

export const awardXp = async (userId: string, delta: number, reason: string, opts?: { sourceType?: string; sourceId?: string }) => {
  if (opts?.sourceType && opts?.sourceId) {
    const existing = await prisma.levelChange.findFirst({ where: { sourceType: opts.sourceType, sourceId: opts.sourceId } });
    if (existing) {
      return { applied: false, reason: 'already_applied' };
    }
  }

  const result = await prisma.$transaction(async (tx) => {
    const lc = await tx.levelChange.create({ data: {
      userId,
      delta,
      reason,
      sourceType: opts?.sourceType,
      sourceId: opts?.sourceId
    }});

    const updatedUser = await tx.user.update({ where: { id: userId }, data: { xp: { increment: delta } }, select: { xp: true } });

    const newLevel = computeLevelFromXp(updatedUser.xp);
    await tx.user.update({ where: { id: userId }, data: { level: newLevel } });

    return { applied: true, levelChange: lc, newLevel };
  });

  return result;
};

export const recomputeLevelForUser = async (userId: string) => {
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { xp: true } });
  if (!user) return null;
  const newLevel = computeLevelFromXp(user.xp);
  await prisma.user.update({ where: { id: userId }, data: { level: newLevel } });
  return newLevel;
};

export const computeDynamicXpFromLikes = async (userId: string) => {
  const result = await prisma.post.aggregate({ where: { userId }, _sum: { likesCount: true } });
  const likes = result._sum.likesCount || 0;
  return likes * 2;
};

export const revokeXp = async (userId: string, delta: number, reason: string, opts?: { sourceType?: string; sourceId?: string }) => {
  const sourceType = opts?.sourceType;
  const sourceId = opts?.sourceId;

  if (sourceType && sourceId) {
    const existing = await prisma.levelChange.findFirst({ where: { sourceType: `${sourceType}_revoke`, sourceId } });
    if (existing) {
      return { applied: false, reason: 'already_revoked' };
    }
  }

  const result = await prisma.$transaction(async (tx) => {
    const lc = await tx.levelChange.create({ data: {
      userId,
      delta: -Math.abs(delta),
      reason,
      sourceType: sourceType ? `${sourceType}_revoke` : undefined,
      sourceId: sourceId
    }});

    const updatedUser = await tx.user.update({ where: { id: userId }, data: { xp: { decrement: Math.abs(delta) } }, select: { xp: true } });
    const newLevel = computeLevelFromXp(updatedUser.xp);
    await tx.user.update({ where: { id: userId }, data: { level: newLevel } });

    return { applied: true, levelChange: lc, newLevel };
  });

  return result;
};

export default { computeLevelFromXp, awardXp, recomputeLevelForUser, computeDynamicXpFromLikes, revokeXp };
