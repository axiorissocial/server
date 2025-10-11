-- CreateTable
CREATE TABLE "LevelChange" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "delta" INTEGER NOT NULL,
    "reason" TEXT NOT NULL,
    "sourceType" TEXT,
    "sourceId" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "LevelChange_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "hasSetPassword" BOOLEAN NOT NULL DEFAULT true,
    "bio" TEXT,
    "level" INTEGER NOT NULL DEFAULT 1,
    "xp" INTEGER NOT NULL DEFAULT 0,
    "isAdmin" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "lastLogin" DATETIME,
    "isVerified" BOOLEAN NOT NULL DEFAULT false,
    "isPrivate" BOOLEAN NOT NULL DEFAULT false,
    "emailVerifiedAt" DATETIME,
    "twoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
    "twoFactorSecret" TEXT,
    "twoFactorRecoveryCodes" JSONB,
    "phoneNumber" TEXT,
    "phoneVerifiedAt" DATETIME
);
INSERT INTO "new_User" ("bio", "createdAt", "email", "emailVerifiedAt", "hasSetPassword", "id", "isAdmin", "isPrivate", "isVerified", "lastLogin", "level", "password", "phoneNumber", "phoneVerifiedAt", "twoFactorEnabled", "twoFactorRecoveryCodes", "twoFactorSecret", "updatedAt", "username") SELECT "bio", "createdAt", "email", "emailVerifiedAt", "hasSetPassword", "id", "isAdmin", "isPrivate", "isVerified", "lastLogin", "level", "password", "phoneNumber", "phoneVerifiedAt", "twoFactorEnabled", "twoFactorRecoveryCodes", "twoFactorSecret", "updatedAt", "username" FROM "User";
DROP TABLE "User";
ALTER TABLE "new_User" RENAME TO "User";
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE INDEX "LevelChange_userId_idx" ON "LevelChange"("userId");

-- CreateIndex
CREATE INDEX "LevelChange_sourceType_sourceId_idx" ON "LevelChange"("sourceType", "sourceId");
