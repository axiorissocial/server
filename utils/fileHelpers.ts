import fs from 'fs';

/**
 * Attempt to unlink a file safely. If unlink fails due to permissions (EACCES/EPERM),
 * try to chmod the file to be writable and retry. Do not throw; just log warnings on failure.
 */
export function safeUnlinkSync(filePath: string) {
  try {
    fs.unlinkSync(filePath);
  } catch (err: any) {
    const code = err && err.code ? String(err.code) : '';
    if (code === 'EACCES' || code === 'EPERM') {
      try {
        // try to make the file writable then unlink again
        try {
          fs.chmodSync(filePath, 0o666);
        } catch (chmodErr) {
          // ignore chmod failures - we'll still attempt unlink
        }
        fs.unlinkSync(filePath);
      } catch (err2) {
        console.warn(`safeUnlinkSync: failed to unlink ${filePath} after chmod attempt:`, err2);
      }
    } else if (code === 'ENOENT') {
      // already gone, nothing to do
    } else {
      console.warn(`safeUnlinkSync: failed to unlink ${filePath}:`, err);
    }
  }
}

export async function safeUnlink(filePath: string) {
  return new Promise<void>((resolve) => {
    try {
      fs.unlink(filePath, async (err: any) => {
        if (!err) return resolve();
        const code = err && err.code ? String(err.code) : '';
        if (code === 'EACCES' || code === 'EPERM') {
          try {
            await fs.promises.chmod(filePath, 0o666).catch(() => undefined);
            await fs.promises.unlink(filePath).catch(() => undefined);
          } catch (_) {
            // swallow
          }
        }
        resolve();
      });
    } catch (e) {
      resolve();
    }
  });
}
