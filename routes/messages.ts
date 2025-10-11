import { Router, Request, Response } from 'express';
import { prisma } from '../index.js';
import { broadcastToUsers } from '../realtime.js';
import { encryptText, decryptText } from '../utils/encryption.js';
import { checkBanned } from '../middleware/checkBanned.js';

const router = Router();

const sanitizeMessage = (message: any) => {
  if (!message) {
    return message;
  }

  return {
    ...message,
    content: decryptText(message.content)
  };
};

const requireAuth = (req: any, res: Response, next: any) => {
  if (!req.session?.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

router.get('/conversations', requireAuth, async (req: any, res: Response) => {
  try {
    const userId = req.session.userId;

    const conversations = await prisma.conversation.findMany({
      where: {
        participants: {
          some: {
            userId: userId
          }
        }
      },
      include: {
        participants: {
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
            }
          }
        },
        lastMessage: {
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
            }
          }
        },
        _count: {
          select: {
            messages: true
          }
        }
      },
      orderBy: {
        updatedAt: 'desc'
      }
    });

    const conversationsWithUnread = await Promise.all(
      conversations.map(async (conversation) => {
        const participant = conversation.participants.find(p => p.userId === userId);
        const unreadCount = await prisma.message.count({
          where: {
            conversationId: conversation.id,
            createdAt: {
              gt: participant?.lastReadAt || new Date(0)
            },
            senderId: {
              not: userId
            }
          }
        });

        return {
          ...conversation,
          lastMessage: conversation.lastMessage ? sanitizeMessage(conversation.lastMessage) : null,
          unreadCount,
          otherParticipants: conversation.participants.filter(p => p.userId !== userId)
        };
      })
    );

    res.json(conversationsWithUnread);
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/conversations', requireAuth, checkBanned, async (req: any, res: Response) => {
  try {
    const userId = req.session.userId;
    const { participantId, participantIds } = req.body;
    const targetParticipantId = participantId || (Array.isArray(participantIds) ? participantIds[0] : undefined);

    if (!targetParticipantId) {
      return res.status(400).json({ error: 'Participant ID is required' });
    }

    if (targetParticipantId === userId) {
      return res.status(400).json({ error: 'Cannot create conversation with yourself' });
    }

    const participant = await prisma.user.findUnique({
      where: { id: targetParticipantId }
    });

    if (!participant) {
      return res.status(404).json({ error: 'User not found' });
    }

    const existingConversation = await prisma.conversation.findFirst({
      where: {
        participants: {
          every: {
            userId: {
              in: [userId, targetParticipantId]
            }
          }
        },
        AND: {
          participants: {
            some: {
              userId: userId
            }
          }
        }
      },
      include: {
        participants: {
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
            }
          }
        }
      }
    });

    if (existingConversation) {
      return res.json({
        ...existingConversation,
        otherParticipants: existingConversation.participants.filter(p => p.userId !== userId)
      });
    }

    const newConversation = await prisma.conversation.create({
      data: {
        participants: {
          create: [
            { userId: userId },
            { userId: targetParticipantId }
          ]
        }
      },
      include: {
        participants: {
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
            }
          }
        }
      }
    });

    res.json({
      ...newConversation,
      otherParticipants: newConversation.participants.filter(p => p.userId !== userId)
    });
  } catch (error) {
    console.error('Error creating conversation:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/conversations/:conversationId/messages', requireAuth, async (req: any, res: Response) => {
  try {
    const userId = req.session.userId;
    const { conversationId } = req.params;
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = (page - 1) * limit;

    const participant = await prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: {
          conversationId,
          userId
        }
      }
    });

    if (!participant) {
      return res.status(403).json({ error: 'You are not a participant in this conversation' });
    }

    const messages = await prisma.message.findMany({
      where: {
        conversationId
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
        readBy: {
          include: {
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
      take: limit
    });

    const totalMessages = await prisma.message.count({
      where: { conversationId }
    });

    const decryptedMessages = messages.map((message: any) => sanitizeMessage(message));

    res.json({
      messages: decryptedMessages.reverse(),
      pagination: {
        page,
        limit,
        total: totalMessages,
        hasNextPage: offset + limit < totalMessages
      }
    });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/conversations/:conversationId/messages', requireAuth, checkBanned, async (req: any, res: Response) => {
  try {
    const userId = req.session.userId;
    const { conversationId } = req.params;
    const { content } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Message content is required' });
    }

    if (content.length > 1000) {
      return res.status(400).json({ error: 'Message is too long (max 1000 characters)' });
    }

    const participant = await prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: {
          conversationId,
          userId
        }
      }
    });

    if (!participant) {
      return res.status(403).json({ error: 'You are not a participant in this conversation' });
    }

    const message = await prisma.$transaction(async (tx) => {
      const newMessage = await tx.message.create({
        data: {
          conversationId,
          senderId: userId,
          content: encryptText(content.trim())
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
          }
        }
      });

      await tx.conversation.update({
        where: { id: conversationId },
        data: {
          lastMessageId: newMessage.id,
          updatedAt: new Date()
        }
      });

      return newMessage;
    });

    const safeMessage = sanitizeMessage(message);

    const participants = await prisma.conversationParticipant.findMany({
      where: { conversationId },
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
        }
      }
    });

    const senderDisplayName = safeMessage.sender.profile?.displayName || safeMessage.sender.username;

    await Promise.all(
      participants.map(async (participant: any) => {
        if (participant.userId === userId) {
          return;
        }

        const unreadMessages = await prisma.message.count({
          where: {
            conversationId,
            createdAt: {
              gt: participant.lastReadAt || new Date(0)
            },
            senderId: {
              not: participant.userId
            }
          }
        });

        const notificationText = unreadMessages > 1
          ? `${senderDisplayName} sent you ${unreadMessages} new messages`
          : `${senderDisplayName} sent you a message`;

        const existingNotification = await prisma.notification.findFirst({
          where: {
            type: 'MESSAGE',
            receiverId: participant.userId,
            conversationId
          }
        });

        if (existingNotification) {
          await prisma.notification.update({
            where: { id: existingNotification.id },
            data: {
              message: notificationText,
              senderId: userId,
              isRead: false,
              isArchived: false,
              archivedAt: null
            }
          });
        } else {
          await prisma.notification.create({
            data: {
              type: 'MESSAGE',
              senderId: userId,
              receiverId: participant.userId,
              conversationId,
              message: notificationText
            }
          });
        }

        const unreadNotifications = await prisma.notification.count({
          where: {
            receiverId: participant.userId,
            isRead: false,
            isArchived: false
          }
        });

        broadcastToUsers([participant.userId], {
          event: 'notification:count',
          data: { count: unreadNotifications }
        });

            if (process.env.NODE_ENV !== 'production') {
              console.debug('[messages] broadcast notification:count to', participant.userId, 'count=', unreadNotifications);
            }

        broadcastToUsers([participant.userId], {
          event: 'message:new',
          data: {
            conversationId,
            message: safeMessage,
            unreadMessages
          }
        });

            if (process.env.NODE_ENV !== 'production') {
              console.debug('[messages] broadcast message:new to', participant.userId, 'conversation=', conversationId);
            }
      })
    );

    broadcastToUsers([userId], {
      event: 'message:sent',
      data: {
        conversationId,
        message: safeMessage
      }
    });

    if (process.env.NODE_ENV !== 'production') {
      console.debug('[messages] broadcast message:sent to sender', userId, 'conversation=', conversationId);
    }

    res.status(201).json(safeMessage);
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete(
  '/conversations/:conversationId/messages/:messageId',
  requireAuth,
  async (req: any, res: Response) => {
    try {
      const userId = req.session.userId;
      const { conversationId, messageId } = req.params;

      const participant = await prisma.conversationParticipant.findUnique({
        where: {
          conversationId_userId: {
            conversationId,
            userId
          }
        }
      });

      if (!participant) {
        return res.status(403).json({ error: 'You are not a participant in this conversation' });
      }

      const message = await prisma.message.findUnique({
        where: { id: messageId },
        include: {
          conversation: {
            select: {
              id: true,
              lastMessageId: true
            }
          }
        }
      });

      if (!message || message.conversationId !== conversationId) {
        return res.status(404).json({ error: 'Message not found' });
      }

      if (message.senderId !== userId) {
        return res.status(403).json({ error: 'You can only delete your own messages' });
      }

      const result = await prisma.$transaction(async (tx) => {
        await tx.messageRead.deleteMany({ where: { messageId } });
        await tx.message.delete({ where: { id: messageId } });

        const wasLastMessage = message.conversation?.lastMessageId === messageId;

        if (wasLastMessage) {
          const nextLastMessage = await tx.message.findFirst({
            where: { conversationId },
            orderBy: { createdAt: 'desc' },
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
              }
            }
          });

          await tx.conversation.update({
            where: { id: conversationId },
            data: {
              lastMessageId: nextLastMessage?.id ?? null,
              updatedAt: nextLastMessage?.createdAt ?? new Date()
            }
          });

          return {
            lastMessage: nextLastMessage
          };
        }

        await tx.conversation.update({
          where: { id: conversationId },
          data: {
            updatedAt: new Date()
          }
        });

        return { lastMessage: null };
      });

      const participants = await prisma.conversationParticipant.findMany({
        where: { conversationId },
        select: { userId: true }
      });

      const recipientIds = participants.map((p) => p.userId);
      const sanitizedLastMessage = result.lastMessage ? sanitizeMessage(result.lastMessage) : null;

      broadcastToUsers(recipientIds, {
        event: 'message:deleted',
        data: {
          conversationId,
          messageId,
          lastMessage: sanitizedLastMessage,
          deletedBy: userId
        }
      });

  res.json({ success: true, lastMessage: sanitizedLastMessage });
    } catch (error) {
      console.error('Error deleting message:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

router.post('/conversations/:conversationId/typing', requireAuth, async (req: any, res: Response) => {
  try {
    const userId = req.session.userId;
    const { conversationId } = req.params;
    const { isTyping } = req.body;

    if (typeof isTyping !== 'boolean') {
      return res.status(400).json({ error: 'isTyping boolean is required' });
    }

    const participant = await prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: {
          conversationId,
          userId
        }
      }
    });

    if (!participant) {
      return res.status(403).json({ error: 'You are not a participant in this conversation' });
    }

    const otherParticipants = await prisma.conversationParticipant.findMany({
      where: {
        conversationId,
        userId: {
          not: userId
        }
      },
      select: {
        userId: true
      }
    });

    if (otherParticipants.length) {
      broadcastToUsers(
        otherParticipants.map((p) => p.userId),
        {
          event: 'message:typing',
          data: {
            conversationId,
            userId,
            isTyping
          }
        }
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error broadcasting typing indicator:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/conversations/:conversationId/read', requireAuth, async (req: any, res: Response) => {
  try {
    const userId = req.session.userId;
    const { conversationId } = req.params;

    const participant = await prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: {
          conversationId,
          userId
        }
      }
    });

    if (!participant) {
      return res.status(403).json({ error: 'You are not a participant in this conversation' });
    }

    await prisma.conversationParticipant.update({
      where: {
        conversationId_userId: {
          conversationId,
          userId
        }
      },
      data: {
        lastReadAt: new Date()
      }
    });

    await prisma.notification.updateMany({
      where: {
        conversationId,
        receiverId: userId,
        type: 'MESSAGE',
        isRead: false
      },
      data: {
        isRead: true
      }
    });

    const unreadNotifications = await prisma.notification.count({
      where: {
        receiverId: userId,
        isRead: false,
        isArchived: false
      }
    });

    broadcastToUsers([userId], {
      event: 'notification:count',
      data: { count: unreadNotifications }
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;