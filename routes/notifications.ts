import express from 'express';
import { PrismaClient, NotificationType } from '../prisma/generated';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth';

const router = express.Router();
const prisma = new PrismaClient();

router.get('/unread-count', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;

    const count = await prisma.notification.count({
      where: {
        receiverId: userId,
        isRead: false,
        isArchived: false
      }
    });

    res.json({ count });
  } catch (error) {
    console.error('Error fetching unread count:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const offset = (page - 1) * limit;
    const view = (req.query.view as string) === 'archived' ? 'archived' : 'active';

    const notifications = await prisma.notification.findMany({
      where: {
        receiverId: userId,
        isArchived: view === 'archived'
      },
      include: {
        sender: {
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
        post: {
          select: {
            id: true,
            title: true,
            content: true
          }
        },
        comment: {
          select: {
            id: true,
            content: true
          }
        },
        conversation: {
          select: {
            id: true
          }
        }
      },
        orderBy: view === 'archived' ? { archivedAt: 'desc' } : { createdAt: 'desc' },
      skip: offset,
      take: limit
    });

    const unreadCount = await prisma.notification.count({
      where: { 
        receiverId: userId,
        isRead: false,
        isArchived: false
      }
    });

    res.json({
      notifications,
      pagination: {
        page,
        limit,
        hasMore: notifications.length === limit
      },
      unreadCount
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

router.put('/:id/read', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;
    const notificationId = req.params.id;

    const notification = await prisma.notification.findFirst({
      where: {
        id: notificationId,
        receiverId: userId
      }
    });

    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    const updated = await prisma.notification.update({
      where: { id: notificationId },
      data: { isRead: true }
    });

    res.json({ success: true, notification: updated });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ error: 'Failed to mark notification as read' });
  }
});

router.put('/read-all', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;

    await prisma.notification.updateMany({
      where: {
        receiverId: userId,
        isRead: false,
        isArchived: false
      },
      data: { isRead: true }
    });

    res.json({ success: true, message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ error: 'Failed to mark all notifications as read' });
  }
});

router.put('/mark-all-read', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;

    await prisma.notification.updateMany({
      where: {
        receiverId: userId,
        isRead: false,
        isArchived: false
      },
      data: { isRead: true }
    });

    res.json({ success: true, message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ error: 'Failed to mark all notifications as read' });
  }
});

router.put('/:id/archive', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;
    const notificationId = req.params.id;

    const notification = await prisma.notification.findFirst({
      where: {
        id: notificationId,
        receiverId: userId,
        isArchived: false
      }
    });

    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    const updated = await prisma.notification.update({
      where: { id: notificationId },
      data: {
        isArchived: true,
        archivedAt: new Date(),
        isRead: true
      }
    });

    res.json({ success: true, notification: updated });
  } catch (error) {
    console.error('Error archiving notification:', error);
    res.status(500).json({ error: 'Failed to archive notification' });
  }
});

router.put('/:id/unarchive', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;
    const notificationId = req.params.id;

    const notification = await prisma.notification.findFirst({
      where: {
        id: notificationId,
        receiverId: userId,
        isArchived: true
      }
    });

    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    const updated = await prisma.notification.update({
      where: { id: notificationId },
      data: {
        isArchived: false,
        archivedAt: null
      }
    });

    res.json({ success: true, notification: updated });
  } catch (error) {
    console.error('Error unarchiving notification:', error);
    res.status(500).json({ error: 'Failed to unarchive notification' });
  }
});

router.delete('/:id', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;
    const notificationId = req.params.id;

    const notification = await prisma.notification.findFirst({
      where: {
        id: notificationId,
        receiverId: userId
      }
    });

    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    await prisma.notification.delete({
      where: { id: notificationId }
    });

    res.json({ success: true, message: 'Notification deleted' });
  } catch (error) {
    console.error('Error deleting notification:', error);
    res.status(500).json({ error: 'Failed to delete notification' });
  }
});

export const createNotification = async (
  type: NotificationType,
  senderId: string | null,
  receiverId: string,
  postId?: string,
  commentId?: string,
  message?: string,
  conversationId?: string
) => {
  try {
    if (senderId === receiverId) return;

    if (type === 'LIKE' && postId) {
      const existing = await prisma.notification.findFirst({
        where: {
          type: 'LIKE',
          senderId,
          receiverId,
          postId,
          createdAt: {
            gte: new Date(Date.now() - 24 * 60 * 60 * 1000)
          }
        }
      });
      if (existing) return;
    }

    await prisma.notification.create({
      data: {
        type,
        senderId,
        receiverId,
        postId,
        commentId,
        message,
        conversationId
      }
    });
  } catch (error) {
    console.error('Error creating notification:', error);
  }
};

export const createMentionNotifications = async (
  content: string,
  senderId: string,
  postId?: string,
  commentId?: string
) => {
  try {
    const mentionRegex = /@(\w+)/g;
    const mentions: string[] = [];
    let match;
    
    while ((match = mentionRegex.exec(content)) !== null) {
      const username = match[1];
      if (!mentions.includes(username)) {
        mentions.push(username);
      }
    }

    for (const username of mentions) {
      const mentionedUser = await prisma.user.findUnique({
        where: { username },
        select: { id: true }
      });
      
      if (mentionedUser && mentionedUser.id !== senderId) {
        await createNotification(
          'MENTION',
          senderId,
          mentionedUser.id,
          postId,
          commentId
        );
      }
    }
  } catch (error) {
    console.error('Error creating mention notifications:', error);
  }
};

export default router;