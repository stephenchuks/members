// src/utils/cache.ts
import Redis from 'ioredis';

const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: Number(process.env.REDIS_PORT),
  password: process.env.REDIS_PASSWORD || undefined,
  lazyConnect: true,
});

redis.on('error', (err) => {
  console.error('❌ Redis error:', err);
});

export async function setCache(key: string, val: string, ttl: number): Promise<void> {
  await redis.set(key, val, 'EX', ttl);
}

export async function getCache(key: string): Promise<string | null> {
  return await redis.get(key);
}

export async function clearCache(key: string): Promise<void> {
  await redis.del(key);
}

// blacklist token on logout
export async function blacklistToken(token: string, ttl: number): Promise<void> {
  await redis.set(`bl_${token}`, '1', 'EX', ttl);
}

export async function isBlacklisted(token: string): Promise<boolean> {
  return (await redis.exists(`bl_${token}`)) === 1;
}
