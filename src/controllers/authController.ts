// src/controllers/authController.ts
import type { RequestHandler } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/User.js';
import {
  setCache,
  getCache,
  clearCache,
  blacklistToken,
} from '../utils/cache.js';

const accessSecret = process.env.JWT_ACCESS_TOKEN_SECRET!;
const refreshSecret = process.env.JWT_REFRESH_TOKEN_SECRET!;
const accessTTL = process.env.JWT_ACCESS_TOKEN_EXPIRES!;   // e.g. "15m"
const refreshTTL = process.env.JWT_REFRESH_TOKEN_EXPIRES!; // e.g. "7d"

// 1. Register
export const register: RequestHandler = async (req, res, next): Promise<void> => {
  try {
    const { email, password, role = 'user' } = req.body as {
      email: string;
      password: string;
      role?: string;
    };
    const hash = await bcrypt.hash(password, 10);
    const u = await User.create({ email, password: hash, role });
    res.status(201).json({ id: u._id, email: u.email, role: u.role });
  } catch (err) {
    next(err);
  }
};

// 2. Login
export const login: RequestHandler = async (req, res, next): Promise<void> => {
  try {
    const { email, password } = req.body as { email: string; password: string };
    const user = await User.findOne({ email }).exec();
    if (!user || !(await bcrypt.compare(password, user.password))) {
      res.status(401).json({ message: 'Invalid credentials' });
      return;
    }
    const payload = { userId: String(user._id), role: user.role };
    const accessToken = jwt.sign(payload, accessSecret, { expiresIn: accessTTL });
    const refreshToken = jwt.sign(payload, refreshSecret, { expiresIn: refreshTTL });
    // store refresh in Redis under "refresh:<userId>"
    await setCache(`refresh:${payload.userId}`, refreshToken, 7 * 24 * 3600);
    res.json({ accessToken, refreshToken });
  } catch (err) {
    next(err);
  }
};

// 3. Refresh
export const refreshToken: RequestHandler = async (req, res, next): Promise<void> => {
  try {
    const { refreshToken: incoming } = req.body as { refreshToken: string };
    const payload = jwt.decode(incoming) as any;
    const userId = String(payload.userId);
    const stored = await getCache(`refresh:${userId}`);
    if (stored !== incoming) {
      res.status(401).json({ message: 'Invalid refresh token' });
      return;
    }
    const newAccess = jwt.sign(
      { userId, role: payload.role },
      accessSecret,
      { expiresIn: accessTTL }
    );
    res.json({ accessToken: newAccess });
  } catch (err) {
    next(err);
  }
};

// 4. Logout
export const logout: RequestHandler = async (req, res, next): Promise<void> => {
  try {
    const header = req.get('Authorization') || '';
    const token = header.slice(7);
    const decoded = jwt.decode(token) as any;
    if (!decoded.exp || !decoded.userId) {
      res.sendStatus(400);
      return;
    }
    const ttl = decoded.exp - Math.floor(Date.now() / 1000);
    await clearCache(`refresh:${decoded.userId}`);
    if (ttl > 0) {
      await blacklistToken(token, ttl);
    }
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};
