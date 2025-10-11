import { PrismaClient } from '../prisma/generated/index.js';
import { Request } from 'express';

const prisma = new PrismaClient();

export const setSessionUser = (req: Request, user: { id: string; username: string; email: string; isAdmin?: boolean }) => {
  req.session.userId = user.id;
  req.session.user = {
    id: user.id,
    username: user.username,
    email: user.email,
  } as any;
  (req.session.user as any).isAdmin = Boolean(user.isAdmin);
};

export async function findUserByUsernameCaseInsensitive(username: string) {
  const lower = username.toLowerCase();
  const raw: any = await prisma.$queryRaw`SELECT * FROM "User" WHERE lower(username) = ${lower} LIMIT 1`;
  if (Array.isArray(raw) && raw.length > 0) return raw[0];
  return raw || null;
}

export async function isUsernameTakenCaseInsensitive(username: string) {
  const lower = String(username).toLowerCase();
  const raw: any = await prisma.$queryRaw`SELECT 1 as exists_flag FROM "User" WHERE lower(username) = ${lower} LIMIT 1`;
  return Array.isArray(raw) ? raw.length > 0 : Boolean(raw);
}

export default {
  setSessionUser,
  findUserByUsernameCaseInsensitive,
  isUsernameTakenCaseInsensitive,
};
