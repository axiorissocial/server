import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import speakeasy from 'speakeasy';
import { prisma } from '../index.js';
import { loginLimiter, registerLimiter, authLimiter } from '../utils/rateLimiters.js';
import { setSessionUser as setSessionUserHelper, isUsernameTakenCaseInsensitive } from '../utils/userAccounts.js';
import { containsProfanityStrict } from '../utils/profanity.js';
import { getRandomGradientId } from '../shared/profileGradients';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

const normalizeEnv = (v?: string | undefined) => (v ? v.trim().replace(/^"|"$/g, '') : undefined);
const FRONTEND_URL = normalizeEnv(process.env.FRONTEND_URL) || 'http://localhost:5173';
const GITHUB_CLIENT_ID = normalizeEnv(process.env.GITHUB_CLIENT_ID) || '';
const GITHUB_CLIENT_SECRET = normalizeEnv(process.env.GITHUB_CLIENT_SECRET) || '';
const GITHUB_SCOPE = 'read:user user:email';
const GITHUB_USER_AGENT = process.env.GITHUB_USER_AGENT || 'HubbleApp';

const GOOGLE_CLIENT_ID = normalizeEnv(process.env.GOOGLE_CLIENT_ID) || '';
const GOOGLE_CLIENT_SECRET = normalizeEnv(process.env.GOOGLE_CLIENT_SECRET) || '';
// Prefer the explicit _RAW env var if present (some setups name it GOOGLE_CALLBACK_URL_RAW)
const GOOGLE_CALLBACK_URL_RAW = normalizeEnv(process.env.GOOGLE_CALLBACK_URL_RAW) || normalizeEnv(process.env.GOOGLE_CALLBACK_URL);
const GOOGLE_SCOPE = 'openid email profile';

const buildGoogleCallbackUrl = (req: Request): string => {
  if (GOOGLE_CALLBACK_URL_RAW) {
    return GOOGLE_CALLBACK_URL_RAW;
  }

  if (FRONTEND_URL) {
    // return `${FRONTEND_URL.replace(/\/$/, '')}/api/auth/google/callback`;
    return `http://localhost:5173/api/auth/google/callback`;
  }

  const proto = (req.get('x-forwarded-proto') || req.protocol || 'http').split(',')[0];
  const host = req.get('x-forwarded-host') || req.get('host') || 'localhost';
  const derived = `${proto}://${host}/api/auth/google/callback`;
  console.warn('Derived Google callback URL from request:', derived, '— consider setting GOOGLE_CALLBACK_URL or FRONTEND_URL in production');
  console.log('Google OAuth config at runtime', { FRONTEND_URL, GOOGLE_CALLBACK_URL_RAW, redirectDerived: derived });
  return derived;
};

const ensureGoogleConfigured = () => Boolean(GOOGLE_CLIENT_ID);

const buildGithubCallbackUrl = (req: Request): string => {
  // 1) Allow an explicit override
  if (process.env.GITHUB_CALLBACK_URL) {
    console.log('Using configured GITHUB_CALLBACK_URL');
    return process.env.GITHUB_CALLBACK_URL;
  }

  // 2) Prefer an explicit FRONTEND_URL env var when present
  if (process.env.FRONTEND_URL) {
    const val = `${process.env.FRONTEND_URL.replace(/\/$/, '')}/api/auth/github/callback`;
    console.log('Using FRONTEND_URL for GitHub callback:', val);
    return val;
  }

  // 3) If the browser included an Origin or Referer header, prefer that origin
  // (useful when frontend runs on a different host than the backend)
  const originHeader = req.get('origin');
  if (originHeader) {
    try {
      const o = new URL(originHeader);
      const val = `${o.origin}/api/auth/github/callback`;
      console.log('Using request Origin header for GitHub callback:', val);
      return val;
    } catch (e) {
      // fallthrough
    }
  }

  const referer = req.get('referer') || req.get('referrer');
  if (referer) {
    try {
      const r = new URL(referer);
      const val = `${r.origin}/api/auth/github/callback`;
      console.log('Using request Referer header for GitHub callback:', val);
      return val;
    } catch (e) {
      // fallthrough
    }
  }

  // 4) Last resort: derive from host/proto (may be localhost in some dev setups)
  const proto = (req.get('x-forwarded-proto') || req.protocol || 'http').split(',')[0];
  const host = req.get('x-forwarded-host') || req.get('host') || 'localhost';
  const derived = `${proto}://${host}/api/auth/github/callback`;
  console.warn('Derived GitHub callback URL from request:', derived, '— consider setting GITHUB_CALLBACK_URL or FRONTEND_URL in production');
  return derived;
};

const ensureGithubConfigured = () => Boolean(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET);

const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');

const allowedReturnPath = (value?: string | null) => {
  if (!value) {
    return '/';
  }

  try {
    if (value.startsWith('http://') || value.startsWith('https://')) {
      const parsed = new URL(value);
      const frontendOrigin = new URL(FRONTEND_URL).origin;
      if (parsed.origin === frontendOrigin) {
        return `${parsed.pathname}${parsed.search}${parsed.hash}` || '/';
      }
      return '/';
    }

    if (value.startsWith('/')) {
      return value;
    }
  } catch (error) {
    console.warn('Invalid returnTo provided, defaulting to /:', error);
  }

  return '/';
};

const createFrontendRedirectUrl = (
  returnTo: string | null | undefined,
  params: Record<string, string | undefined>,
  req?: Request
) => {
  const targetPath = allowedReturnPath(returnTo);

  // Determine base frontend origin in this order:
  // 1. Explicit FRONTEND_URL env
  // 2. Request Origin header
  // 3. Request Referer header
  // 4. Fallback to default FRONTEND_URL constant
  let base = FRONTEND_URL;
  if (!process.env.FRONTEND_URL && req) {
    const originHeader = req.get('origin');
    if (originHeader) {
      try {
        base = new URL(originHeader).origin;
      } catch (e) {
        // ignore and try referer
      }
    }

    if (!base || base === 'http://localhost:5173') {
      const referer = req.get('referer') || req.get('referrer');
      if (referer) {
        try {
          base = new URL(referer).origin;
        } catch (e) {
          // ignore
        }
      }
    }
  }

  const url = new URL(targetPath, base);
  Object.entries(params).forEach(([key, value]) => {
    if (typeof value === 'string' && value.length > 0) {
      url.searchParams.set(key, value);
    }
  });
  return url.toString();
};

// use helper from server/utils/userAccounts.ts
const setSessionUser = setSessionUserHelper;

const generateUniqueUsername = async (base: string): Promise<string> => {
  const sanitizedBase = base.toLowerCase().replace(/[^a-z0-9.]/g, '') || 'githubuser';
  let candidate = sanitizedBase;
  let suffix = 0;

  while (suffix < 5000) {
    // Case-insensitive check: ensure no existing user uses the same characters when lowercased
    const candidateLower = candidate.toLowerCase();
    const exists = await isUsernameTakenCaseInsensitive(candidate);
    if (!exists) {
      return candidate;
    }
    suffix += 1;
    candidate = `${sanitizedBase}${suffix}`;
  }

  return `${sanitizedBase}${randomToken(3)}`;
};

const createRandomPasswordHash = async () => {
  const secret = randomToken(32);
  return bcrypt.hash(secret, 12);
};

const provider = 'github' as const;

const googleProvider = 'google' as const;

router.get('/auth/google', (req: Request, res: Response) => {
  console.log('Google auth requested (start)', { sessionID: (req as any).sessionID, sessionUserId: req.session?.userId, hasOAuthState: Boolean(req.session?.oauthState) });

  if (!ensureGoogleConfigured()) {
    console.warn('Google OAuth redirect attempted but GOOGLE_CLIENT_ID is missing');
    return res.status(503).json({ message: 'Google OAuth is not configured (missing client id)' });
  }

  if (!GOOGLE_CLIENT_SECRET) {
    console.warn('Google CLIENT_ID present but CLIENT_SECRET missing — redirect will proceed but callback will fail unless CLIENT_SECRET is set');
  }

  const mode = req.query.mode === 'link' ? 'link' : 'login';
  if (mode === 'link' && !req.session.userId) {
    return res.status(401).json({ message: 'You must be logged in to link accounts' });
  }

  const state = randomToken(16);
  const returnTo = typeof req.query.returnTo === 'string' ? req.query.returnTo : null;
  req.session.oauthState = {
    provider: googleProvider,
    state,
    mode,
    userId: req.session.userId ?? null,
    returnTo,
  };

  console.log('Saved oauthState on session (start):', { sessionID: (req as any).sessionID, oauthState: req.session.oauthState });

  const redirectUri = buildGoogleCallbackUrl(req);
  const deviceId = process.env.OAUTH_DEVICE_ID || req.get('x-forwarded-for') || req.hostname || 'local-device';
  const deviceName = process.env.OAUTH_DEVICE_NAME || (`${req.get('user-agent')?.split(' ')[0] || 'Axioris'}-dev`);

    // Normalize device values to strings and save them to the session so we can reuse them
    const normalizedDeviceId = String(deviceId ?? 'local-device');
    const normalizedDeviceName = String(deviceName ?? 'Axioris-dev');
    (req.session as any).oauthDevice = { id: normalizedDeviceId, name: normalizedDeviceName };

    const params = new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      response_type: 'code',
      scope: GOOGLE_SCOPE,
      state,
      redirect_uri: redirectUri,
      access_type: 'offline',
      prompt: 'consent',
      device_id: normalizedDeviceId,
      device_name: normalizedDeviceName,
    });

  const authorizeUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  console.log('Initiating Google OAuth redirect', { redirectUri, authorizeUrl });

  req.session.save((err) => {
    if (err) {
      console.error('Failed to persist OAuth state (google):', err);
      return res.status(500).json({ message: 'Failed to initiate Google authentication' });
    }
    // Read back the session file/store to confirm oauthState persisted (for debugging)
    try {
        console.log('Session saved (start) ok', { sessionID: (req as any).sessionID, oauthState: req.session.oauthState, oauthDevice: (req.session as any).oauthDevice });
    } catch (e) {
      console.warn('Unable to log session after save (start):', e);
    }
    res.redirect(authorizeUrl);
  });
});

router.get('/auth/google/callback', async (req: Request, res: Response) => {
  console.log('Google callback hit', { sessionID: (req as any).sessionID, sessionUserId: req.session?.userId, hasOAuthState: Boolean(req.session?.oauthState) });
  const sessionState = req.session.oauthState;
  const stateParam = typeof req.query.state === 'string' ? req.query.state : '';
  const code = typeof req.query.code === 'string' ? req.query.code : '';

  const redirectWithStatus = (status: 'success' | 'linked' | 'unlinked' | 'error' | 'username_conflict', message?: string) => {
    const redirectUrl = createFrontendRedirectUrl(sessionState?.returnTo, {
      authProvider: googleProvider,
      authStatus: status,
      authMessage: message,
    }, req);
    return res.redirect(redirectUrl);
  };

  if (!ensureGoogleConfigured()) {
    return redirectWithStatus('error', 'google_not_configured');
  }

  if (!sessionState || sessionState.provider !== googleProvider || !stateParam || sessionState.state !== stateParam) {
    console.warn('Google OAuth state mismatch', { sessionID: (req as any).sessionID, sessionState, stateParam });
    return redirectWithStatus('error', 'invalid_oauth_state');
  }

  delete req.session.oauthState;

  if (!code) {
    return redirectWithStatus('error', 'missing_code');
  }

  try {
    if (!GOOGLE_CLIENT_SECRET) {
      console.error('Google callback attempted but GOOGLE_CLIENT_SECRET is missing');
      return redirectWithStatus('error', 'server_missing_secret');
    }

    // Reuse device info we stored on the session during the authorize phase (if any)
    const sessionDevice = (req.session as any)?.oauthDevice;
    const deviceIdForExchange = sessionDevice?.id || process.env.OAUTH_DEVICE_ID || 'local-device';
    const deviceNameForExchange = sessionDevice?.name || process.env.OAUTH_DEVICE_NAME || 'Axioris-dev';

    console.log('Exchanging token with device info', { deviceIdForExchange, deviceNameForExchange });

    const tokenBody = new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: buildGoogleCallbackUrl(req),
      grant_type: 'authorization_code',
      device_id: String(deviceIdForExchange),
      device_name: String(deviceNameForExchange),
    });

    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: tokenBody.toString()
    });

    if (!tokenResponse.ok) {
      throw new Error(`Google token exchange failed with status ${tokenResponse.status}`);
    }

    const tokenData = await tokenResponse.json() as any;
    const accessToken = tokenData.access_token;

    const profileResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      }
    });

    if (!profileResponse.ok) {
      throw new Error(`Google profile request failed with status ${profileResponse.status}`);
    }

    const profile = await profileResponse.json() as any;
    // profile contains: sub (id), email, email_verified, name, picture, given_name, family_name

    const providerAccountId = String(profile.sub);
    const accountData = {
      provider: googleProvider,
      providerAccountId,
      username: profile.email ? profile.email.split('@')[0] : null,
      displayName: profile.name ?? null,
      profileUrl: null,
      avatarUrl: profile.picture ?? null,
      accessToken,
      scope: tokenData.scope ?? GOOGLE_SCOPE,
      tokenExpiresAt: null as Date | null,
    };

    const existingAccount = await (prisma as any).oAuthAccount.findUnique({
      where: {
        provider_providerAccountId: {
          provider: googleProvider,
          providerAccountId,
        },
      },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            email: true,
            isAdmin: true,
          },
        },
      },
    });

    if (sessionState.mode === 'link') {
      if (!sessionState.userId) {
        return redirectWithStatus('error', 'missing_session_user');
      }

      if (existingAccount && existingAccount.userId !== sessionState.userId) {
        return redirectWithStatus('error', 'already_linked_elsewhere');
      }

      await prisma.$transaction(async (tx) => {
        await (tx as any).oAuthAccount.upsert({
          where: {
            provider_providerAccountId: {
              provider: googleProvider,
              providerAccountId,
            }
          },
          update: {
            username: accountData.username,
            displayName: accountData.displayName,
            profileUrl: accountData.profileUrl,
            avatarUrl: accountData.avatarUrl,
            accessToken: accountData.accessToken,
            scope: accountData.scope,
            updatedAt: new Date(),
            userId: sessionState.userId!,
          },
          create: {
            provider: googleProvider,
            providerAccountId,
            username: accountData.username,
            displayName: accountData.displayName,
            profileUrl: accountData.profileUrl,
            avatarUrl: accountData.avatarUrl,
            accessToken: accountData.accessToken,
            scope: accountData.scope,
            userId: sessionState.userId!,
          }
        });
      });

      return redirectWithStatus('linked');
    }

    if (existingAccount?.user) {
      setSessionUser(req, existingAccount.user);
      await (prisma as any).oAuthAccount.update({
        where: { id: existingAccount.id },
        data: {
          username: accountData.username,
          displayName: accountData.displayName,
          profileUrl: accountData.profileUrl,
          avatarUrl: accountData.avatarUrl,
          accessToken: accountData.accessToken,
          scope: accountData.scope,
          updatedAt: new Date(),
        }
      });

      await prisma.user.update({
        where: { id: existingAccount.user.id },
        data: { lastLogin: new Date() }
      });

      await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve(null)));
      return redirectWithStatus('success');
    }

    // Rest of account creation/linking logic mirrors GitHub flow below (reuse existing code paths)
    let targetUser: { id: string; username: string; email: string; isAdmin: boolean } | null = null;
    if (profile.email) {
      targetUser = await prisma.user.findUnique({
        where: { email: profile.email },
        select: {
          id: true,
          username: true,
          email: true,
          isAdmin: true,
        },
      });
    }

    if (!targetUser) {
      const rawBase = accountData.username ?? profile.name ?? `google${profile.sub}`;
      const baseUsername = String(rawBase).toLowerCase().replace(/[^a-z0-9.]/g, '') || `google${profile.sub}`;

      const usernameTaken = await isUsernameTakenCaseInsensitive(baseUsername);
      if (usernameTaken) {
        (req.session as any).googleSignupData = {
          profile,
          accountData,
          email: profile.email,
          emailVerified: profile.email_verified ?? false,
          baseUsername,
          returnTo: sessionState.returnTo
        };
        await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve(null)));
        return redirectWithStatus('username_conflict', baseUsername);
      }

      const hashedPassword = await createRandomPasswordHash();
      const avatarGradient = getRandomGradientId();
      let bannerGradient = getRandomGradientId();
      if (bannerGradient === avatarGradient) {
        bannerGradient = getRandomGradientId();
      }

      const user = await prisma.user.create({
        data: {
          username: baseUsername,
          email: profile.email ?? undefined,
          password: hashedPassword,
          profile: {
            create: {
              displayName: accountData.displayName || baseUsername,
              avatarGradient,
              bannerGradient
            } as any
          },
          settings: {
            create: {
              language: 'en',
              theme: 'dark'
            }
          }
        },
        select: {
          id: true,
          username: true,
          email: true,
          isAdmin: true,
          createdAt: true,
          profile: {
            select: {
              id: true,
              displayName: true,
              avatarGradient: true,
              bannerGradient: true
            } as any
          }
        }
      });

      await (prisma as any).oAuthAccount.create({
        data: {
          provider: googleProvider,
          providerAccountId,
          username: accountData.username,
          displayName: accountData.displayName,
          profileUrl: accountData.profileUrl,
          avatarUrl: accountData.avatarUrl,
          accessToken: accountData.accessToken,
          scope: accountData.scope,
          userId: user.id
        }
      });

      req.session.userId = user.id;
      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email,
      } as any;
      (req.session.user as any).isAdmin = user.isAdmin ?? false;

      await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve(null)));

      return redirectWithStatus('success');
    }

    // If targetUser exists (found by email), link account
    await prisma.$transaction(async (tx) => {
      await (tx as any).oAuthAccount.create({
        data: {
          provider: googleProvider,
          providerAccountId,
          username: accountData.username,
          displayName: accountData.displayName,
          profileUrl: accountData.profileUrl,
          avatarUrl: accountData.avatarUrl,
          accessToken: accountData.accessToken,
          scope: accountData.scope,
          userId: targetUser!.id
        }
      });
    });

    setSessionUser(req, { id: targetUser.id, username: targetUser.username, email: targetUser.email, isAdmin: targetUser.isAdmin });
    await prisma.user.update({ where: { id: targetUser.id }, data: { lastLogin: new Date() } });
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve(null)));
    return redirectWithStatus('success');
  } catch (error) {
    console.error('Google OAuth error:', error);
    return redirectWithStatus('error', 'internal_error');
  }
});

router.get('/auth/github', (req: Request, res: Response) => {
  if (!ensureGithubConfigured()) {
    return res.status(503).json({ message: 'GitHub OAuth is not configured' });
  }

  const mode = req.query.mode === 'link' ? 'link' : 'login';
  if (mode === 'link' && !req.session.userId) {
    return res.status(401).json({ message: 'You must be logged in to link accounts' });
  }

  const state = randomToken(16);
  const returnTo = typeof req.query.returnTo === 'string' ? req.query.returnTo : null;
  req.session.oauthState = {
    provider,
    state,
    mode,
    userId: req.session.userId ?? null,
    returnTo,
  };

  const redirectUri = buildGithubCallbackUrl(req);
  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    scope: GITHUB_SCOPE,
    state,
    allow_signup: 'true',
    redirect_uri: redirectUri,
  });

  req.session.save((err) => {
    if (err) {
      console.error('Failed to persist OAuth state:', err);
      return res.status(500).json({ message: 'Failed to initiate GitHub authentication' });
    }
    res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
  });
});

router.get('/auth/github/callback', async (req: Request, res: Response) => {
  const sessionState = req.session.oauthState;
  const stateParam = typeof req.query.state === 'string' ? req.query.state : '';
  const code = typeof req.query.code === 'string' ? req.query.code : '';

  const redirectWithStatus = (status: 'success' | 'linked' | 'unlinked' | 'error' | 'username_conflict', message?: string) => {
    const redirectUrl = createFrontendRedirectUrl(sessionState?.returnTo, {
      authProvider: provider,
      authStatus: status,
      authMessage: message,
    }, req);
    return res.redirect(redirectUrl);
  };

  if (!ensureGithubConfigured()) {
    return redirectWithStatus('error', 'github_not_configured');
  }

  if (!sessionState || sessionState.provider !== provider || !stateParam || sessionState.state !== stateParam) {
    return redirectWithStatus('error', 'invalid_oauth_state');
  }

  delete req.session.oauthState;

  if (!code) {
    return redirectWithStatus('error', 'missing_code');
  }

  try {
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: buildGithubCallbackUrl(req),
      }),
    });

    if (!tokenResponse.ok) {
      throw new Error(`GitHub token exchange failed with status ${tokenResponse.status}`);
    }

    const tokenData = await tokenResponse.json() as { access_token?: string; scope?: string; token_type?: string; error?: string };
    if (!tokenData.access_token) {
      throw new Error(`GitHub token exchange failed: ${tokenData.error ?? 'unknown_error'}`);
    }

    const accessToken = tokenData.access_token;
    const githubHeaders = {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': GITHUB_USER_AGENT,
    } satisfies Record<string, string>;

    const profileResponse = await fetch('https://api.github.com/user', {
      headers: githubHeaders,
    });

    if (!profileResponse.ok) {
      throw new Error(`GitHub profile request failed with status ${profileResponse.status}`);
    }

    const profile = await profileResponse.json() as {
      id: number;
      login?: string;
      name?: string;
      email?: string;
      avatar_url?: string;
      html_url?: string;
      bio?: string;
      blog?: string;
      company?: string;
    };

    if (!profile || typeof profile.id !== 'number') {
      throw new Error('Invalid GitHub profile response');
    }

    let emails: Array<{ email: string; verified: boolean; primary: boolean }> = [];
    try {
      const emailsResponse = await fetch('https://api.github.com/user/emails', {
        headers: githubHeaders,
      });
      if (emailsResponse.ok) {
        const json = await emailsResponse.json();
        if (Array.isArray(json)) {
          emails = json.filter((entry): entry is { email: string; verified: boolean; primary: boolean } => typeof entry?.email === 'string');
        }
      }
    } catch (error) {
      console.warn('Failed to fetch GitHub user emails:', error);
    }

    const primaryEmail = emails.find(item => item.primary && item.verified)
      ?? emails.find(item => item.primary)
      ?? emails.find(item => item.verified)
      ?? emails[0];

    let email = primaryEmail?.email ?? (typeof profile.email === 'string' ? profile.email : null);
    const emailVerified = Boolean(primaryEmail?.verified);
    if (!email) {
      email = `github_${profile.id}@users.noreply.github.com`;
    }

    const providerAccountId = String(profile.id);

  const existingAccount = await (prisma as any).oAuthAccount.findUnique({
      where: {
        provider_providerAccountId: {
          provider,
          providerAccountId,
        },
      },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            email: true,
            isAdmin: true,
          },
        },
      },
    });

    const accountData = {
      provider,
      providerAccountId,
      username: profile.login ?? null,
      displayName: profile.name ?? null,
      profileUrl: profile.html_url ?? null,
      avatarUrl: profile.avatar_url ?? null,
      accessToken,
      scope: tokenData.scope ?? GITHUB_SCOPE,
      tokenExpiresAt: null as Date | null,
    };

    if (sessionState.mode === 'link') {
      if (!sessionState.userId) {
        return redirectWithStatus('error', 'missing_session_user');
      }

      if (existingAccount && existingAccount.userId !== sessionState.userId) {
        return redirectWithStatus('error', 'already_linked_elsewhere');
      }

      await prisma.$transaction(async (tx) => {
        const user = await tx.user.findUnique({ where: { id: sessionState.userId! }, select: { id: true } });
        if (!user) {
          throw new Error('User not found for linking');
        }

        await (tx as any).oAuthAccount.upsert({
          where: {
            provider_providerAccountId: {
              provider,
              providerAccountId,
            }
          },
          update: {
            username: accountData.username,
            displayName: accountData.displayName,
            profileUrl: accountData.profileUrl,
            avatarUrl: accountData.avatarUrl,
            accessToken: accountData.accessToken,
            scope: accountData.scope,
            updatedAt: new Date(),
            userId: sessionState.userId!,
          },
          create: {
            provider,
            providerAccountId,
            username: accountData.username,
            displayName: accountData.displayName,
            profileUrl: accountData.profileUrl,
            avatarUrl: accountData.avatarUrl,
            accessToken: accountData.accessToken,
            scope: accountData.scope,
            userId: sessionState.userId!,
          }
        });
      });

      return redirectWithStatus('linked');
    }

    if (existingAccount?.user) {
      setSessionUser(req, existingAccount.user);
      await (prisma as any).oAuthAccount.update({
        where: { id: existingAccount.id },
        data: {
          username: accountData.username,
          displayName: accountData.displayName,
          profileUrl: accountData.profileUrl,
          avatarUrl: accountData.avatarUrl,
          accessToken: accountData.accessToken,
          scope: accountData.scope,
          updatedAt: new Date(),
        }
      });

      await prisma.user.update({
        where: { id: existingAccount.user.id },
        data: { lastLogin: new Date() }
      });

      await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve(null)));
      return redirectWithStatus('success');
    }

    let targetUser: { id: string; username: string; email: string; isAdmin: boolean } | null = null;
    if (email) {
      targetUser = await prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
          username: true,
          email: true,
          isAdmin: true,
        },
      });
    }

    if (!targetUser) {
  const rawBase = profile.login ?? profile.name ?? `github${profile.id}`;
  const baseUsername = String(rawBase).toLowerCase().replace(/[^a-z0-9.]/g, '') || `github${profile.id}`;
      
      const baseUsernameLower = baseUsername.toLowerCase();
      const existingUserWithUsername = await isUsernameTakenCaseInsensitive(baseUsername);

      if (existingUserWithUsername) {
        (req.session as any).githubSignupData = {
          profile,
          accountData,
          email,
          emailVerified,
          baseUsername,
          returnTo: sessionState.returnTo
        };
        await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve(null)));
        return redirectWithStatus('username_conflict', baseUsername);
      }

      const hashedPassword = await createRandomPasswordHash();
      const avatarGradient = getRandomGradientId();
      let bannerGradient = getRandomGradientId();
      if (bannerGradient === avatarGradient) {
        bannerGradient = getRandomGradientId();
      }

      targetUser = await prisma.user.create({
        data: {
          username: baseUsername,
          email,
          password: hashedPassword,
          isVerified: emailVerified,
          emailVerifiedAt: emailVerified ? new Date() : null,
          lastLogin: new Date(),
          profile: {
            create: {
              displayName: profile.name ?? baseUsername,
              avatarGradient,
              bannerGradient,
            }
          },
        } as any,
        select: {
          id: true,
          username: true,
          email: true,
          isAdmin: true,
        },
      });
    } else {
      await prisma.user.update({
        where: { id: targetUser.id },
        data: {
          lastLogin: new Date(),
          emailVerifiedAt: emailVerified ? (targetUser as any).emailVerifiedAt ?? new Date() : (targetUser as any).emailVerifiedAt,
        } as any,
      });
    }

    await (prisma as any).oAuthAccount.create({
      data: {
        provider,
        providerAccountId,
        username: accountData.username,
        displayName: accountData.displayName,
        profileUrl: accountData.profileUrl,
        avatarUrl: accountData.avatarUrl,
        accessToken: accountData.accessToken,
        scope: accountData.scope,
        userId: targetUser!.id,
      }
    });

    setSessionUser(req, targetUser!);
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve(null)));
    return redirectWithStatus('success');

  } catch (error) {
    console.error('GitHub OAuth callback error:', error);
    return redirectWithStatus('error', 'github_oauth_failed');
  }
});

router.get('/auth/providers', requireAuth, async (req: Request, res: Response) => {
  try {
    const accounts = await (prisma as any).oAuthAccount.findMany({
      where: { userId: req.session.userId! },
      select: {
        provider: true,
        username: true,
        profileUrl: true,
        avatarUrl: true,
        createdAt: true,
      }
    });

    res.json({ providers: accounts });
  } catch (error) {
    console.error('Failed to load linked providers:', error);
    res.status(500).json({ message: 'Failed to load linked providers' });
  }
});

router.delete('/auth/providers/:provider', requireAuth, async (req: Request, res: Response) => {
  const providerParam = String(req.params.provider || '').toLowerCase();

  if (providerParam !== provider) {
    return res.status(400).json({ message: 'Unsupported provider' });
  }

  try {
    const linkedAccounts: Array<{ id: string; provider: string }> = await (prisma as any).oAuthAccount.findMany({
      where: { userId: req.session.userId! },
      select: { id: true, provider: true },
    });

    if (!linkedAccounts.some((account) => account.provider === provider)) {
      return res.status(404).json({ message: 'Provider not linked' });
    }

    const user = await prisma.user.findUnique({
      where: { id: req.session.userId! },
      select: { password: true },
    });

    const otherProviders = linkedAccounts.filter((account) => account.provider !== provider);
    if (!user?.password && otherProviders.length === 0) {
      return res.status(400).json({ message: 'Cannot unlink the only sign-in method' });
    }

    await (prisma as any).oAuthAccount.deleteMany({
      where: {
        userId: req.session.userId!,
        provider,
      }
    });

    res.json({ message: 'Provider unlinked successfully' });
  } catch (error) {
    console.error('Failed to unlink provider:', error);
    res.status(500).json({ message: 'Failed to unlink provider' });
  }
});

router.post('/auth/set-password', requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = req.session.userId!;
    const { password } = req.body as { password?: string };

    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    const user = await prisma.user.findUnique({ where: { id: userId }, include: { oauthAccounts: true } });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!user.oauthAccounts || user.oauthAccounts.length === 0) {
      return res.status(400).json({ message: 'Not an OAuth-only account' });
    }

    if (user.hasSetPassword) {
      return res.status(400).json({ message: 'Password already set' });
    }

    const hash = await bcrypt.hash(password, 12);
    await prisma.user.update({ where: { id: userId }, data: { password: hash, hasSetPassword: true } });

    res.json({ message: 'Password set successfully' });
  } catch (err) {
    console.error('Set password error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    user?: {
      id: string;
      username: string;
      email: string;
    };
    viewedPosts?: Record<string, number>;
    oauthState?: {
      provider: 'github' | 'google' | string;
      state: string;
      mode: 'login' | 'link';
      userId?: string | null;
      returnTo?: string | null;
    };
    pendingTwoFactorUserId?: string;
    pendingTwoFactorRemember?: boolean;
  }
}

router.post('/register', registerLimiter, async (req: Request, res: Response) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    const usernameRegex = /^[a-zA-Z0-9.]+$/;
    if (!usernameRegex.test(name)) {
      return res.status(400).json({ message: 'Username can only contain letters, numbers, and periods' });
    }

    if (containsProfanityStrict(name)) {
      return res.status(400).json({ message: 'Username contains disallowed language' });
    }

    // Check email conflict first
    const existingByEmail = await prisma.user.findUnique({ where: { email } });
    if (existingByEmail) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // Case-insensitive username check
    const nameLower = String(name).toLowerCase();
    const existingByUsername = await isUsernameTakenCaseInsensitive(name);
    if (existingByUsername) {
      return res.status(400).json({ message: 'Username already taken' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const avatarGradient = getRandomGradientId();
    let bannerGradient = getRandomGradientId();
    while (bannerGradient === avatarGradient) {
      bannerGradient = getRandomGradientId();
    }

    const user = await prisma.user.create({
      data: {
        username: name,
        email,
        password: hashedPassword,
        profile: {
          create: {
            displayName: name,
            avatarGradient,
            bannerGradient
          } as any
        },
        settings: {
          create: {
            language: 'en',
            theme: 'dark'
          }
        }
      },
      select: {
        id: true,
        username: true,
        email: true,
        isAdmin: true,
        createdAt: true,
        profile: {
          select: {
            id: true,
            displayName: true,
            avatarGradient: true,
            bannerGradient: true
          } as any
        }
      }
    });

    req.session.userId = user.id;
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
    };
    (req.session.user as any).isAdmin = user.isAdmin ?? false;

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin ?? false,
        profile: (user as any).profile
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.post('/login', loginLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password, remember } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email/username and password are required' });
    }

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email },
          { username: email }
        ]
      },
      select: {
        id: true,
        username: true,
        email: true,
        isAdmin: true,
        password: true,
        twoFactorEnabled: true,
      }
    });

    if (!user) {
      return res.status(401).json({ message: 'Invalid email/username or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid email/username or password' });
    }

    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      // Store temporary login data in session
      req.session.pendingTwoFactorUserId = user.id;
      req.session.pendingTwoFactorRemember = remember || false;
      
      return res.json({
        requires2FA: true,
        message: '2FA verification required'
      });
    }

    // No 2FA - complete login normally
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() }
    });

    req.session.userId = user.id;
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
    };
    (req.session.user as any).isAdmin = user.isAdmin ?? false;

    if (remember) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
    }

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin ?? false,
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 2FA verification endpoint for login
router.post('/login/2fa', loginLimiter, async (req: Request, res: Response) => {
  try {
    const { token, recoveryCode } = req.body;

    // Check if there's a pending 2FA login
    if (!req.session.pendingTwoFactorUserId) {
      return res.status(400).json({ message: 'No pending 2FA login found' });
    }

    if (!token && !recoveryCode) {
      return res.status(400).json({ message: '2FA code or recovery code is required' });
    }

    const userId = req.session.pendingTwoFactorUserId;
    const remember = req.session.pendingTwoFactorRemember || false;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        email: true,
        isAdmin: true,
        twoFactorEnabled: true,
        twoFactorSecret: true,
        twoFactorRecoveryCodes: true,
      }
    });

    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      // Clear pending 2FA data
      delete req.session.pendingTwoFactorUserId;
      delete req.session.pendingTwoFactorRemember;
      return res.status(400).json({ message: 'Invalid 2FA login attempt' });
    }

    let verified = false;
    let usedRecoveryCode = false;

    // Try recovery code first
    if (recoveryCode && user.twoFactorRecoveryCodes) {
      const codes = user.twoFactorRecoveryCodes as string[];
      const codeIndex = codes.indexOf(recoveryCode.toUpperCase());
      
      if (codeIndex !== -1) {
        verified = true;
        usedRecoveryCode = true;
        
        // Remove used recovery code
        const updatedCodes = codes.filter((_, index) => index !== codeIndex);
        await prisma.user.update({
          where: { id: userId },
          data: { twoFactorRecoveryCodes: updatedCodes }
        });
      }
    }

    // Try TOTP token if recovery code didn't work
    if (!verified && token) {
      verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
        window: 2
      });
    }

    if (!verified) {
      return res.status(401).json({ message: 'Invalid 2FA code' });
    }

    // 2FA verified - complete login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() }
    });

    // Clear pending 2FA data
    delete req.session.pendingTwoFactorUserId;
    delete req.session.pendingTwoFactorRemember;

    // Set session user
    req.session.userId = user.id;
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
    };
    (req.session.user as any).isAdmin = user.isAdmin ?? false;

    if (remember) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
    }

    res.json({
      message: '2FA verification successful',
      usedRecoveryCode,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin ?? false,
      }
    });

  } catch (error) {
    console.error('2FA login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});


router.post('/logout', (req: Request, res: Response) => {
  req.session.destroy((err: any) => {
    if (err) {
      return res.status(500).json({ message: 'Could not log out' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out successfully' });
  });
});

router.get('/me', async (req: Request, res: Response) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
      select: {
        id: true,
        username: true,
        email: true,
        bio: true,
        level: true,
        isVerified: true,
        isAdmin: true,
        createdAt: true,
        profile: {
          select: {
            displayName: true,
            avatar: true,
            location: true,
            website: true,
            banner: true,
            avatarGradient: true,
            bannerGradient: true
          } as any
        }
      }
    });

    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({ message: 'User not found' });
    }

    if (req.session.user) {
      (req.session.user as any).isAdmin = user.isAdmin;
    }

    res.json({ user });

  } catch (error) {
    console.error('Auth check error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

router.get('/check-username', async (req: Request, res: Response) => {
  try {
    const { username } = req.query;
    
    if (!username || typeof username !== 'string') {
      return res.status(400).json({ error: 'Username is required' });
    }

    const usernameRegex = /^[a-zA-Z0-9.]+$/;
    if (!usernameRegex.test(username)) {
      return res.json({ available: false, reason: 'invalid_format' });
    }

    const existingUser = await prisma.user.findUnique({
      where: { username },
      select: { id: true }
    });

    res.json({ available: !existingUser });
  } catch (error) {
    console.error('Username check error:', error);
    res.status(500).json({ error: 'Failed to check username availability' });
  }
});

router.post('/complete-github-signup', async (req: Request, res: Response) => {
  try {
    const { username } = req.body;
    const githubData = (req.session as any).githubSignupData;

    if (!githubData) {
      return res.status(400).json({ error: 'No GitHub signup session found' });
    }

    if (!username || typeof username !== 'string') {
      return res.status(400).json({ error: 'Username is required' });
    }

    const usernameRegex = /^[a-zA-Z0-9.]+$/;
    if (!usernameRegex.test(username)) {
      return res.status(400).json({ error: 'Username can only contain letters, numbers, and periods' });
    }

    if (containsProfanityStrict(username)) {
      return res.status(400).json({ error: 'Username contains disallowed language' });
    }

    const existingUser = await prisma.user.findUnique({
      where: { username },
      select: { id: true }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Username is already taken' });
    }

    const { profile, accountData, email, emailVerified } = githubData;
    const hashedPassword = await createRandomPasswordHash();
    const avatarGradient = getRandomGradientId();
    let bannerGradient = getRandomGradientId();
    if (bannerGradient === avatarGradient) {
      bannerGradient = getRandomGradientId();
    }

    const result = await prisma.$transaction(async (tx) => {
      const newUser = await tx.user.create({
        data: {
          username,
          email,
          password: hashedPassword,
          hasSetPassword: false,
          isVerified: false,
          emailVerifiedAt: null,
          lastLogin: new Date(),
          profile: {
            create: {
              displayName: profile.name ?? username,
              avatarGradient,
              bannerGradient,
            } as any
          },
          settings: {
            create: {
              language: 'en',
              theme: 'dark'
            }
          }
        },
        select: {
          id: true,
          username: true,
          email: true,
          isAdmin: true,
        },
      });

      const providerAccountId = String(profile.id);
      await (tx as any).oAuthAccount.create({
        data: {
          provider: 'github',
          providerAccountId,
          userId: newUser.id,
          username: accountData.username,
          displayName: accountData.displayName,
          profileUrl: accountData.profileUrl,
          avatarUrl: accountData.avatarUrl,
          accessToken: accountData.accessToken,
          scope: accountData.scope,
        }
      });

      return newUser;
    });

    setSessionUser(req, result);
    
    delete (req.session as any).githubSignupData;
    
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve(null)));

    res.json({ 
      success: true, 
      user: result,
      returnTo: githubData.returnTo || '/'
    });

  } catch (error) {
    console.error('Complete GitHub signup error:', error);
    res.status(500).json({ error: 'Failed to complete GitHub signup' });
  }
});

router.post('/oauth/unlink', async (req: Request, res: Response) => {
  try {
    const userId = (req.session as any)?.userId;
    if (!userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const { provider } = req.body;
    if (!provider || typeof provider !== 'string') {
      return res.status(400).json({ error: 'Provider is required' });
    }

    const oauthAccount = await prisma.oAuthAccount.findFirst({
      where: {
        userId,
        provider
      }
    });

    if (!oauthAccount) {
      return res.status(404).json({ error: 'OAuth account not found' });
    }

    await prisma.oAuthAccount.delete({
      where: {
        id: oauthAccount.id
      }
    });

    res.json({ success: true, message: 'OAuth account unlinked successfully' });
  } catch (error) {
    console.error('OAuth unlink error:', error);
    res.status(500).json({ error: 'Failed to unlink OAuth account' });
  }
});

export default router;