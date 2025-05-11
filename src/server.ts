// src/server.ts
import dotenv from 'dotenv';
dotenv.config();

import connectMongo from './config/db.js';
import { connectRedis } from './config/redis.js';
import app from './app.js';

const start = async () => {
  // 1. Connect databases
  await connectMongo();
  await connectRedis();

  // 2. Start HTTP server
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`🚀 Server listening on port ${PORT}`);
  });
};

start().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
