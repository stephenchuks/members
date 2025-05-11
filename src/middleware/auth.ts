// src/middleware/auth.ts
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import { isBlacklisted } from '../utils/cache.js';

const accessSecret = process.env.JWT_ACCESS_TOKEN_SECRET!;

export interface AuthRequest extends Request {
  user: { userId: string; role: string };
}

export const authenticate: RequestHandler = async (
  req, res, next
): Promise<void> => {
  const header = req.get('Authorization') || '';
  if (!header.startsWith('Bearer ')) {
    res.status(401).json({ message: 'Missing token' });
    return;
  }
  const token = header.slice(7);
  if (await isBlacklisted(token)) {
    res.status(401).json({ message: 'Token revoked' });
    return;
  }
  try {
    const payload = jwt.verify(token, accessSecret) as any;
    (req as AuthRequest).user = {
      userId: String(payload.userId),
      role: String(payload.role),
    };
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};

export const authorize =
  (allowed: string[]): RequestHandler =>
  (req, res, next) => {
    const role = (req as AuthRequest).user.role;
    if (!allowed.includes(role)) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }
    next();
  };
