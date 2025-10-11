import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const VERSION_TAG = 'ENC.v1.';

const rawKey = process.env.MESSAGE_ENCRYPTION_KEY || process.env.SESSION_SECRET || 'development-only-key';

if (!process.env.MESSAGE_ENCRYPTION_KEY) {
  console.warn('[encryption] MESSAGE_ENCRYPTION_KEY is not set. Using a fallback key intended for development only.');
}

const KEY = crypto.createHash('sha256').update(rawKey).digest();

export const isEncrypted = (value?: string | null): boolean => {
  return typeof value === 'string' && value.startsWith(VERSION_TAG);
};

export const encryptText = (plainText: string): string => {
  if (!plainText) {
    return plainText;
  }

  if (isEncrypted(plainText)) {
    return plainText;
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const payload = Buffer.concat([iv, authTag, ciphertext]).toString('base64');

  return `${VERSION_TAG}${payload}`;
};

export const decryptText = (value?: string | null): string => {
  if (!value) {
    return '';
  }

  if (!isEncrypted(value)) {
    return value;
  }

  try {
    const payload = Buffer.from(value.substring(VERSION_TAG.length), 'base64');
    const iv = payload.subarray(0, 12);
    const authTag = payload.subarray(12, 28);
    const ciphertext = payload.subarray(28);

    const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (error) {
    console.error('[encryption] Failed to decrypt text', error);
    return value;
  }
};
