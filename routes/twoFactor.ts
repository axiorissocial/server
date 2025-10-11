import { Router, Request, Response } from 'express';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import bcrypt from 'bcrypt';
import { PrismaClient } from '../prisma/generated/index.js';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth.js';
import { checkBanned } from '../middleware/checkBanned.js';
import crypto from 'crypto';

const router = Router();
const prisma = new PrismaClient();

// Generate recovery codes
function generateRecoveryCodes(count: number = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}`);
  }
  return codes;
}

// Generate 2FA secret and QR code
router.post('/2fa/generate', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.userId!;
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { username: true, email: true, twoFactorEnabled: true }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is already enabled' });
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Axioris (${user.username})`,
      issuer: 'Axioris',
      length: 32
    });

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!);

    res.json({
      secret: secret.base32,
      qrCode: qrCodeUrl,
      otpauthUrl: secret.otpauth_url
    });
  } catch (error) {
    console.error('Error generating 2FA secret:', error);
    res.status(500).json({ error: 'Failed to generate 2FA secret' });
  }
});

// Enable 2FA
router.post('/2fa/enable', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.userId!;
    const { token, secret } = req.body;

    if (!token || !secret) {
      return res.status(400).json({ error: 'Token and secret are required' });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { twoFactorEnabled: true }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is already enabled' });
    }

    // Verify the token
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2 // Allow 2 time steps before and after
    });

    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Generate recovery codes
    const recoveryCodes = generateRecoveryCodes();

    // Enable 2FA
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: true,
        twoFactorSecret: secret,
        twoFactorRecoveryCodes: recoveryCodes
      }
    });

    res.json({
      success: true,
      message: '2FA enabled successfully',
      recoveryCodes
    });
  } catch (error) {
    console.error('Error enabling 2FA:', error);
    res.status(500).json({ error: 'Failed to enable 2FA' });
  }
});

// Disable 2FA
router.post('/2fa/disable', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.userId!;
    const { password, token } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { 
        password: true, 
        twoFactorEnabled: true, 
        twoFactorSecret: true 
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is not enabled' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // If user has 2FA enabled, they must provide a valid token
    if (token) {
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret!,
        encoding: 'base32',
        token: token,
        window: 2
      });

      if (!verified) {
        return res.status(400).json({ error: 'Invalid 2FA code' });
      }
    }

    // Disable 2FA
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorRecoveryCodes: []
      }
    });

    res.json({
      success: true,
      message: '2FA disabled successfully'
    });
  } catch (error) {
    console.error('Error disabling 2FA:', error);
    res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

// Verify 2FA code (for login)
router.post('/2fa/verify', async (req: Request, res: Response) => {
  try {
    const { userId, token, recoveryCode } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    if (!token && !recoveryCode) {
      return res.status(400).json({ error: 'Token or recovery code is required' });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { 
        twoFactorEnabled: true, 
        twoFactorSecret: true,
        twoFactorRecoveryCodes: true
      }
    });

    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({ error: 'Invalid verification attempt' });
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

    // Try TOTP token
    if (!verified && token) {
      verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
        window: 2
      });
    }

    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    res.json({
      success: true,
      message: '2FA verification successful',
      usedRecoveryCode
    });
  } catch (error) {
    console.error('Error verifying 2FA:', error);
    res.status(500).json({ error: 'Failed to verify 2FA code' });
  }
});

// Get 2FA status
router.get('/2fa/status', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.userId!;
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { 
        twoFactorEnabled: true,
        twoFactorRecoveryCodes: true
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const recoveryCodesCount = user.twoFactorRecoveryCodes 
      ? (user.twoFactorRecoveryCodes as string[]).length 
      : 0;

    res.json({
      enabled: user.twoFactorEnabled,
      recoveryCodesRemaining: recoveryCodesCount
    });
  } catch (error) {
    console.error('Error fetching 2FA status:', error);
    res.status(500).json({ error: 'Failed to fetch 2FA status' });
  }
});

// Regenerate recovery codes
router.post('/2fa/recovery-codes/regenerate', requireAuth, checkBanned, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.userId!;
    const { password, token } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { 
        password: true,
        twoFactorEnabled: true,
        twoFactorSecret: true
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is not enabled' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Verify 2FA token
    if (!token) {
      return res.status(400).json({ error: '2FA code is required' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret!,
      encoding: 'base32',
      token: token,
      window: 2
    });

    if (!verified) {
      return res.status(400).json({ error: 'Invalid 2FA code' });
    }

    // Generate new recovery codes
    const recoveryCodes = generateRecoveryCodes();

    await prisma.user.update({
      where: { id: userId },
      data: { twoFactorRecoveryCodes: recoveryCodes }
    });

    res.json({
      success: true,
      recoveryCodes
    });
  } catch (error) {
    console.error('Error regenerating recovery codes:', error);
    res.status(500).json({ error: 'Failed to regenerate recovery codes' });
  }
});

export default router;
