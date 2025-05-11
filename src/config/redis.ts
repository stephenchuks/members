// src/config/redis.ts
import type { Redis as RedisClientType, RedisOptions } from 'ioredis';
import IORedis from 'ioredis';

// ioredis’s ESM export ends up as a module namespace, so we extract the class:
const RedisClass = (IORedis as unknown) as new (opts?: RedisOptions) => RedisClientType;

const redis = new RedisClass({
  host: process.env.REDIS_HOST,
  port: Number(process.env.REDIS_PORT),
  password: process.env.REDIS_PASSWORD || undefined,
  lazyConnect: true,
});

redis.on('error', (err: unknown) => {
  console.error('❌ Redis error:', err);
});

export const connectRedis = async (): Promise<void> => {
  try {
    await redis.connect();
    console.log('✅ Redis connected');
  } catch (err: unknown) {
    console.error('❌ Redis connection error:', err);
    process.exit(1);
  }
};

export default redis;
