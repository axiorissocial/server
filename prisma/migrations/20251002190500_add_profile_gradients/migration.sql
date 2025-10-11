-- Add gradient preference columns for profile media defaults
ALTER TABLE "Profile" ADD COLUMN "avatarGradient" TEXT;
ALTER TABLE "Profile" ADD COLUMN "bannerGradient" TEXT;
