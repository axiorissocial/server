import express from 'express';
import bcrypt from 'bcrypt';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import rateLimit from 'express-rate-limit';

const AVATARS_DIR = path.join(process.cwd(), 'public', 'uploads', 'avatars');
const BANNERS_DIR = path.join(process.cwd(), 'public', 'uploads', 'banners');
import { PrismaClient } from '../prisma/generated/index.js';
import { containsProfanityStrict } from '../utils/profanity.js';
import { addUrl, removeUrl } from '../utils/sitemapCache.js';

const router = express.Router();
const prisma = new PrismaClient();

const requireAuth = (req: any, res: any, next: any) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

const profileGradientsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: {
    error: 'Too many profile gradient update requests from this IP. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(process.cwd(), 'public', 'uploads', 'avatars');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `avatar-${uniqueSuffix}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

const bannerStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync(BANNERS_DIR)) {
      fs.mkdirSync(BANNERS_DIR, { recursive: true });
    }
    cb(null, BANNERS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `banner-${uniqueSuffix}${ext}`);
  }
});

const bannerUpload = multer({
  storage: bannerStorage,
  limits: {
    fileSize: 8 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

router.get('/users/me/profile', requireAuth, async (req: any, res: any) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
      include: {
        profile: true
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      bio: user.bio,
      hasSetPassword: user.hasSetPassword,
      profile: user.profile
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/account/update', requireAuth, async (req: any, res: any) => {
  try {
    const { username, email, currentPassword, newPassword } = req.body;
    const userId = req.session.userId;

    const currentUser = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        oauthAccounts: true
      }
    });

    if (!currentUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isOAuthUser = currentUser.oauthAccounts.length > 0;
    const needsCurrentPassword = !isOAuthUser || currentUser.hasSetPassword;
    
    if (needsCurrentPassword) {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current password is required' });
      }
      const isPasswordValid = await bcrypt.compare(currentPassword, currentUser.password);
      if (!isPasswordValid) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }
    }

    if (username !== currentUser.username) {
      const existingUser = await prisma.user.findUnique({ where: { username } });
      if (existingUser && existingUser.id !== userId) {
        return res.status(400).json({ error: 'Username already taken' });
      }

      const usernameRegex = /^[a-zA-Z0-9.]+$/;
      if (!usernameRegex.test(username)) {
        return res.status(400).json({ error: 'Username can only contain letters, numbers, and periods' });
      }

      if (containsProfanityStrict(username)) {
        return res.status(400).json({ error: 'Username contains disallowed language' });
      }
    }

    if (email !== currentUser.email) {
      const existingEmail = await prisma.user.findUnique({
        where: { email }
      });
      if (existingEmail && existingEmail.id !== userId) {
        return res.status(400).json({ error: 'Email already in use' });
      }
    }

    const updateData: any = {
      username,
      email
    };

    if (newPassword) {
      if (newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters' });
      }
      updateData.password = await bcrypt.hash(newPassword, 10);
      
      if (isOAuthUser && !currentUser.hasSetPassword) {
        updateData.hasSetPassword = true;
      }
    }

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: updateData,
      select: {
        id: true,
        username: true,
        email: true,
        bio: true,
        level: true,
        isVerified: true,
        createdAt: true
      }
    });

    try {
      const base = (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
      if (currentUser.username && currentUser.username !== updatedUser.username) {
        removeUrl(`${base}/profile/${encodeURIComponent(currentUser.username)}`);
        removeUrl(`${base}/profile/@${encodeURIComponent(currentUser.username)}`);
      }
      addUrl({ loc: `${base}/profile/${encodeURIComponent(updatedUser.username)}`, lastmod: updatedUser.createdAt?.toISOString() ?? new Date().toISOString(), changefreq: 'weekly', priority: '0.6' });
      addUrl({ loc: `${base}/profile/@${encodeURIComponent(updatedUser.username)}`, lastmod: updatedUser.createdAt?.toISOString() ?? new Date().toISOString(), changefreq: 'weekly', priority: '0.6' });
    } catch (err) {
      console.error('Failed to update sitemap cache after account update:', err);
    }

    res.json({
      message: 'Account updated successfully',
      user: updatedUser
    });
  } catch (error) {
    console.error('Error updating account:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/users/profile', requireAuth, async (req: any, res: any) => {
  try {
    const { displayName, bio, location, website, birthDate } = req.body;
    const userId = req.session.userId;

    let parsedBirthDate = null;
    if (birthDate) {
      parsedBirthDate = new Date(birthDate);
      if (isNaN(parsedBirthDate.getTime())) {
        return res.status(400).json({ error: 'Invalid birth date' });
      }
    }

    if (displayName && containsProfanityStrict(displayName)) {
      return res.status(400).json({ error: 'Display name contains disallowed language' });
    }

    const profile = await prisma.profile.upsert({
      where: { userId },
      update: {
        displayName: displayName || null,
        bio: bio || null,
        location: location || null,
        website: website || null,
        birthDate: parsedBirthDate
      },
      create: {
        userId,
        displayName: displayName || null,
        bio: bio || null,
        location: location || null,
        website: website || null,
        birthDate: parsedBirthDate
      }
    });

    res.json({
      message: 'Profile updated successfully',
      profile
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/users/profile/gradients', profileGradientsLimiter, requireAuth, async (req: any, res: any) => {
  try {
    const userId = req.session.userId;
    const { avatarGradient, bannerGradient, clearAvatar, clearBanner } = req.body ?? {};

    const updateData: {
      avatarGradient?: string | null;
      bannerGradient?: string | null;
      avatar?: string | null;
      banner?: string | null;
    } = {};

    const shouldClearAvatar = Boolean(clearAvatar);
    const shouldClearBanner = Boolean(clearBanner);

    if (avatarGradient !== undefined) {
      if (avatarGradient !== null && typeof avatarGradient !== 'string') {
        return res.status(400).json({ error: 'Invalid avatar gradient' });
      }
      updateData.avatarGradient = avatarGradient ? String(avatarGradient) : null;
    }

    if (bannerGradient !== undefined) {
      if (bannerGradient !== null && typeof bannerGradient !== 'string') {
        return res.status(400).json({ error: 'Invalid banner gradient' });
      }
      updateData.bannerGradient = bannerGradient ? String(bannerGradient) : null;
    }

    const currentProfile = await prisma.profile.findUnique({ where: { userId } });

    if (shouldClearAvatar) {
      if (currentProfile?.avatar) {
        const avatarPath = path.join(process.cwd(), 'public', currentProfile.avatar);
        if (fs.existsSync(avatarPath)) {
          fs.unlinkSync(avatarPath);
        }
      }
      updateData.avatar = null;
    }

    if (shouldClearBanner) {
      if (currentProfile?.banner) {
        const bannerPath = path.join(process.cwd(), 'public', currentProfile.banner);
        if (fs.existsSync(bannerPath)) {
          fs.unlinkSync(bannerPath);
        }
      }
      updateData.banner = null;
    }

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ error: 'No gradient values provided' });
    }

    const profile = await prisma.profile.upsert({
      where: { userId },
      update: updateData as any,
      create: {
        userId,
        ...updateData
      } as any
    });

    const profileWithGradients = profile as any;

    res.json({
      message: 'Profile gradients updated successfully',
      gradients: {
        avatarGradient: profileWithGradients.avatarGradient ?? null,
        bannerGradient: profileWithGradients.bannerGradient ?? null
      },
      media: {
        avatar: profileWithGradients.avatar ?? null,
        banner: profileWithGradients.banner ?? null
      }
    });
  } catch (error) {
    console.error('Error updating profile gradients:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/users/profile/avatar', requireAuth, upload.single('avatar'), async (req: any, res: any) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const userId = req.session.userId;
    const avatarPath = `/uploads/avatars/${req.file.filename}`;

    const currentProfile = await prisma.profile.findUnique({
      where: { userId }
    });

    if (currentProfile?.avatar) {
      const oldAvatarPath = path.join(process.cwd(), 'public', currentProfile.avatar);
      if (fs.existsSync(oldAvatarPath)) {
        fs.unlinkSync(oldAvatarPath);
      }
    }

    const profile = await prisma.profile.upsert({
      where: { userId },
      update: {
        avatar: avatarPath,
        avatarGradient: null
      } as any,
      create: {
        userId,
        avatar: avatarPath,
        avatarGradient: null
      } as any
    });

    res.json({
      message: 'Avatar uploaded successfully',
      avatar: avatarPath,
      gradients: {
        avatarGradient: null,
        bannerGradient: (profile as any).bannerGradient ?? null
      }
    });
  } catch (error) {
    console.error('Error uploading avatar:', error);
    
    if (req.file) {
      const filePath = req.file.path;
      const resolvedPath = path.resolve(filePath);
      if (resolvedPath.startsWith(AVATARS_DIR) && fs.existsSync(resolvedPath)) {
        fs.unlinkSync(resolvedPath);
      }
    }
    
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/users/profile/banner', requireAuth, bannerUpload.single('banner'), async (req: any, res: any) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const userId = req.session.userId;
    const bannerPath = `/uploads/banners/${req.file.filename}`;

    const currentProfile = await prisma.profile.findUnique({
      where: { userId }
    });

    if (currentProfile?.banner) {
      const oldBannerPath = path.join(process.cwd(), 'public', currentProfile.banner);
      if (fs.existsSync(oldBannerPath)) {
        fs.unlinkSync(oldBannerPath);
      }
    }

    const profile = await prisma.profile.upsert({
      where: { userId },
      update: {
        banner: bannerPath,
        bannerGradient: null
      } as any,
      create: {
        userId,
        banner: bannerPath,
        bannerGradient: null
      } as any
    });

    res.json({
      message: 'Banner uploaded successfully',
      banner: bannerPath,
      gradients: {
        bannerGradient: null,
        avatarGradient: (profile as any).avatarGradient ?? null
      }
    });
  } catch (error) {
    console.error('Error uploading banner:', error);

    if (req.file) {
      const filePath = req.file.path;
      const resolvedPath = path.resolve(filePath);
      if (resolvedPath.startsWith(BANNERS_DIR) && fs.existsSync(resolvedPath)) {
        fs.unlinkSync(resolvedPath);
      }
    }

    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/users/profile/avatar', requireAuth, async (req: any, res: any) => {
  try {
    const userId = req.session.userId;

    const currentProfile = await prisma.profile.findUnique({
      where: { userId }
    });

    if (!currentProfile?.avatar) {
      return res.status(400).json({ error: 'No avatar to delete' });
    }

    const avatarPath = path.join(process.cwd(), 'public', currentProfile.avatar);
    if (fs.existsSync(avatarPath)) {
      fs.unlinkSync(avatarPath);
    }

    await prisma.profile.update({
      where: { userId },
      data: {
        avatar: null
      }
    });

    res.json({
      message: 'Avatar deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting avatar:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/users/profile/banner', requireAuth, async (req: any, res: any) => {
  try {
    const userId = req.session.userId;

    const currentProfile = await prisma.profile.findUnique({
      where: { userId }
    });

    if (!currentProfile?.banner) {
      return res.status(400).json({ error: 'No banner to delete' });
    }

    const bannerPath = path.join(process.cwd(), 'public', currentProfile.banner);
    if (fs.existsSync(bannerPath)) {
      fs.unlinkSync(bannerPath);
    }

    await prisma.profile.update({
      where: { userId },
      data: {
        banner: null
      }
    });

    res.json({
      message: 'Banner deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting banner:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/account/delete', requireAuth, async (req: any, res: any) => {
  try {
    const userId = req.session.userId;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password confirmation required' });
    }

    const currentUser = await prisma.user.findUnique({
      where: { id: userId },
      include: { profile: true }
    });

    if (!currentUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, currentUser.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Incorrect password' });
    }

    if (currentUser.profile?.avatar) {
      const avatarPath = path.join(process.cwd(), 'public', currentUser.profile.avatar);
      if (fs.existsSync(avatarPath)) {
        try {
          fs.unlinkSync(avatarPath);
          console.log('Deleted avatar file:', avatarPath);
        } catch (error) {
          console.warn('Failed to delete avatar file:', error);
        }
      }
    }

    if (currentUser.profile?.banner) {
      const bannerPath = path.join(process.cwd(), 'public', currentUser.profile.banner);
      if (fs.existsSync(bannerPath)) {
        try {
          fs.unlinkSync(bannerPath);
          console.log('Deleted banner file:', bannerPath);
        } catch (error) {
          console.warn('Failed to delete banner file:', error);
        }
      }
    }

    const deleted = await prisma.user.delete({
      where: { id: userId }
    });

    try {
      const base = (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
      const uname = deleted.username;
      const { removeUrl } = await import('../utils/sitemapCache.js');
      removeUrl(`${base}/profile/${encodeURIComponent(uname)}`);
      removeUrl(`${base}/profile/@${encodeURIComponent(uname)}`);
    } catch (err) {
      console.error('Failed to update sitemap cache after account deletion:', err);
    }

    console.log(`Successfully deleted user account: ${userId}`);

    req.session.destroy((err: any) => {
      if (err) {
        console.error('Error destroying session:', err);
      }
    });

    res.json({
      message: 'Account deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/users/me/oauth-accounts', requireAuth, async (req: any, res: any) => {
  try {
    const userId = req.session.userId;

    const accounts = await prisma.oAuthAccount.findMany({
      where: { userId },
      select: {
        id: true,
        provider: true,
        username: true,
        displayName: true,
        profileUrl: true,
        avatarUrl: true,
        createdAt: true
      }
    });

    res.json({ accounts });
  } catch (error) {
    console.error('Error fetching OAuth accounts:', error);
    res.status(500).json({ error: 'Failed to fetch OAuth accounts' });
  }
});

export default router;