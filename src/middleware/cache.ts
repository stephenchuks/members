// src/middleware/cache.ts
import type { Request, Response, NextFunction } from 'express';
import {
  generateMembersCacheKey,
  getCached,
  setCache,
  clearMembersCache,
} from '../utils/cache.js';

export const cacheMembersList = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const key = generateMembersCacheKey(req.query as any);
  const cached = await getCached(key);
  if (cached) {
    res.json(JSON.parse(cached));
    return;
  }
  const originalJson = res.json.bind(res);
  res.json = (body: any) => {
    setCache(key, JSON.stringify(body)).catch(console.error);
    return originalJson(body);
  };
  next();
};

export { clearMembersCache };
