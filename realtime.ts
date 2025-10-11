import type { Server } from 'http';
import type { IncomingMessage } from 'http';
import type session from 'express-session';
import { WebSocketServer, WebSocket } from 'ws';

interface SessionRequest extends IncomingMessage {
  session?: session.Session & { userId?: string };
}

type SessionMiddleware = (req: IncomingMessage, res: any, next: (err?: unknown) => void) => void;

type RealtimeEventPayload = {
  event: string;
  data?: unknown;
};

const userSockets = new Map<string, Set<WebSocket>>();
let wss: WebSocketServer | null = null;
let sessionParser: SessionMiddleware | null = null;

const broadcastToAll = (payload: RealtimeEventPayload) => {
  const message = JSON.stringify(payload);

  for (const sockets of userSockets.values()) {
    for (const ws of sockets) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(message);
      }
    }
  }
};

const broadcastPresenceUpdate = (userId: string, isOnline: boolean) => {
  broadcastToAll({
    event: 'presence:update',
    data: {
      userId,
      status: isOnline ? 'online' : 'offline'
    }
  });
};

export const initRealtime = (server: Server, sessionMiddleware: SessionMiddleware) => {
  sessionParser = sessionMiddleware;
  wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (request, socket, head) => {
    if (!request.url?.startsWith('/ws') && !request.url?.startsWith('/api/ws')) {
      socket.destroy();
      return;
    }

    sessionParser?.(request, {} as any, (err) => {
      if (process.env.NODE_ENV !== 'production') {
        try {
          console.debug('[realtime] upgrade request headers:', {
            cookie: request.headers.cookie,
            url: request.url,
            remoteAddress: (request.socket && (request.socket as any).remoteAddress) || null
          });
        } catch (e) {}
      }

      if (err) {
        socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
        socket.destroy();
        return;
      }

      const sessionRequest = request as SessionRequest;

      if (process.env.NODE_ENV !== 'production') {
        console.debug('[realtime] parsed session on upgrade:', sessionRequest.session);
      }

      const userId = sessionRequest.session?.userId;

      if (!userId) {
        if (process.env.NODE_ENV !== 'production') {
          console.debug('[realtime] websocket upgrade rejected: no userId in session');
        }
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      wss?.handleUpgrade(request, socket, head, (ws) => {
        bindSocket(ws, userId);
      });
    });
  });
};

const bindSocket = (ws: WebSocket, userId: string) => {
  if (!userSockets.has(userId)) {
    userSockets.set(userId, new Set());
  }

  const sockets = userSockets.get(userId)!;
  const wasOnline = sockets.size > 0;
  sockets.add(ws);

  const cleanupSocket = () => {
    const userSet = userSockets.get(userId);
    if (!userSet) {
      return;
    }

    userSet.delete(ws);
    if (userSet.size === 0) {
      userSockets.delete(userId);
      broadcastPresenceUpdate(userId, false);
    }
  };

  ws.on('close', cleanupSocket);
  ws.on('error', cleanupSocket);

  if (process.env.NODE_ENV !== 'production') {
    console.debug('[realtime] socket bound for user', userId, 'totalSocketsForUser=', sockets.size, 'remote=', ((ws as any)._socket && (ws as any)._socket.remoteAddress) || null);
  }

  safeSend(ws, { event: 'connection:ack' });
  safeSend(ws, {
    event: 'presence:state',
    data: {
      userIds: Array.from(userSockets.keys())
    }
  });

  if (!wasOnline) {
    broadcastPresenceUpdate(userId, true);
  }
};

const safeSend = (ws: WebSocket, payload: RealtimeEventPayload) => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
};

export const broadcastToUsers = (userIds: string[], payload: RealtimeEventPayload) => {
  if (!userIds.length) {
    return;
  }

  const message = JSON.stringify(payload);

  if (process.env.NODE_ENV !== 'production') {
    console.debug('[realtime] broadcastToUsers event=', payload.event, 'targets=', userIds);
  }

  for (const userId of userIds) {
    const sockets = userSockets.get(userId);
    if (!sockets) continue;

    for (const ws of sockets) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(message);
      }
    }
  }
};

export const getRealtimeStats = () => {
  return Array.from(userSockets.entries()).map(([userId, sockets]) => ({ userId, count: sockets.size }));
};

export const hasRealtime = () => Boolean(wss);
