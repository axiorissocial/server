import express, { Request, Response } from 'express';
import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';
import session from 'express-session';
import FileStore from 'session-file-store';
import path from 'path';
import lusca from 'lusca';
import http from 'http';
import { PrismaClient } from './prisma/generated/index.js';
import authRoutes from './routes/auth.js';
import sitemapRoutes from './routes/sitemap.js';
import postRoutes from './routes/posts.js';
import accountRoutes from './routes/account.js';
import profileRoutes from './routes/profiles.js';
import messageRoutes from './routes/messages.js';
import notificationRoutes from './routes/notifications.js';
import reportRoutes from './routes/reports.js';
import adminRoutes from './routes/admin.js';
import twoFactorRoutes from './routes/twoFactor.js';
import ssrRoutes from './routes/ssr.js';
import dotenv from 'dotenv';
import { initRealtime } from './realtime.js';
import { getRealtimeStats } from './realtime.js';
import { i18next, i18nextMiddleware, getAvailableLanguages } from './i18n.js';
import { initSitemapCache } from './utils/sitemapCache.js';

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3001;

const FileStoreSession = FileStore(session);

const isSecureCookie = process.env.NODE_ENV === 'production' || process.env.FORCE_SECURE_COOKIES === 'true';

const sessionMiddleware = session({
  store: new FileStoreSession({
    path: path.join(process.cwd(), 'sessions'),
    ttl: 24 * 60 * 60,
    reapInterval: 60 * 60,
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isSecureCookie,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    // Use 'none' in secure contexts to allow cross-site requests to include cookies
    sameSite: isSecureCookie ? 'none' : 'lax',
  },
});

app.set('trust proxy', 1);

// Configure CORS dynamically so the Access-Control-Allow-Origin header
// matches the incoming request origin (needed when sending credentials).
const rawWhitelist = (process.env.CORS_WHITELIST || process.env.FRONTEND_URL || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// Add common local dev hosts if not already present
const devHosts = ['http://localhost:5173', 'http://127.0.0.1:5173'];
for (const h of devHosts) {
  if (!rawWhitelist.includes(h)) rawWhitelist.push(h);
}

const corsOptions = {
  origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    // allow non-browser tools or same-origin requests where origin is undefined
    if (!origin) return callback(null, true);
    if (rawWhitelist.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'x-csrf-token'],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
// Ensure preflight requests are handled (use regex path to avoid path-to-regexp '*' parsing issues)
app.options(/.*/, cors(corsOptions));

app.use(i18nextMiddleware.handle(i18next));

// Security headers
app.use(helmet());

// Gzip compression
app.use(compression());

// Basic global rate limiting
import { generalApiLimiter } from './utils/rateLimiters.js';
app.use('/api', generalApiLimiter);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(sessionMiddleware);
app.use(lusca.csrf({ header: 'x-csrf-token' }));

app.get('/api/csrf-token', (req: Request, res: Response) => {
  const tokenGenerator = (req as Request & { csrfToken?: () => string }).csrfToken;

  if (!tokenGenerator) {
    res.status(500).json({ error: 'CSRF token generator unavailable' });
    return;
  }

  const csrfToken = tokenGenerator();
  res.setHeader('Cache-Control', 'no-store');
  res.json({ csrfToken });
});

// Serve uploads. Rely on the global CORS middleware above (do not set a wildcard
// origin here as that breaks credentialed requests and will conflict with the
// dynamic CORS policy).
app.use('/uploads', express.static(path.join(process.cwd(), 'public', 'uploads')));

app.use('/node_modules/@twemoji/svg', express.static(path.join(process.cwd(), 'node_modules', '@twemoji', 'svg')));

app.use('/api', authRoutes);
app.use('/api', twoFactorRoutes);
app.use('/api', postRoutes);
app.use('/api', accountRoutes);
app.use('/api/users', profileRoutes);
app.use('/api', messageRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api', reportRoutes);
app.use('/api', adminRoutes);

app.use('/', sitemapRoutes);

// SSR routes for social media crawlers - MUST be before static file serving
app.use('/', ssrRoutes);

// Serve public static assets (should come after SSR routes)
app.use(express.static(path.join(process.cwd(), 'public')));

app.get('/api/i18n/languages', (req: Request, res: Response) => {
  res.json({ languages: getAvailableLanguages() });
});

if (process.env.NODE_ENV !== 'production') {
  app.get('/api/debug/realtime', (req: Request, res: Response) => {
    try {
      const stats = getRealtimeStats();
      res.json({ stats });
    } catch (err) {
      res.status(500).json({ error: 'Unable to fetch realtime stats' });
    }
  });

  app.get('/api/debug/oauth-config', (req: Request, res: Response) => {
    res.json({
      GITHUB_CLIENT_ID: Boolean(process.env.GITHUB_CLIENT_ID),
      GITHUB_CLIENT_SECRET: Boolean(process.env.GITHUB_CLIENT_SECRET),
      GOOGLE_CLIENT_ID: Boolean(process.env.GOOGLE_CLIENT_ID),
      GOOGLE_CLIENT_SECRET: Boolean(process.env.GOOGLE_CLIENT_SECRET),
    });
  });
}

app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', message: req.t('backend.health') });
});

process.on('SIGINT', async () => {
  await prisma.$disconnect();
  process.exit(0);
});

const server = http.createServer(app);

initRealtime(server, sessionMiddleware as any);

initSitemapCache([{ loc: (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '') + '/', changefreq: 'daily', priority: '1.0' }])
  .catch(err => console.error('Failed to initialize sitemap cache:', err));

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export { prisma };