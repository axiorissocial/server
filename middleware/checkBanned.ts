import { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '../prisma/generated/index.js';

const prisma = new PrismaClient();

export interface AuthenticatedRequest extends Request {
  userId?: string;
  user?: any;
}

/**
 * Middleware to check if the authenticated user is banned.
 * If banned, returns 403 with ban information.
 * Should be used after requireAuth middleware.
 */
export const checkBanned = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  try {
    if (!req.userId) {
      // No user authenticated, skip ban check
      return next();
    }

    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: {
        isBanned: true,
        bannedAt: true,
        banReason: true,
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isBanned) {
      return res.status(403).json({
        error: 'Account banned',
        banned: true,
        bannedAt: user.bannedAt,
        banReason: user.banReason || 'Your account has been banned from using this service.',
      });
    }

    next();
  } catch (error) {
    console.error('Error checking ban status:', error);
    res.status(500).json({ error: 'Failed to check account status' });
  }
};
