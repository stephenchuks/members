// src/config/jwt.ts
import jsonwebtoken from 'jsonwebtoken';

export const jwt = jsonwebtoken;               // default import of CommonJS module
export const accessTokenSecret = process.env.JWT_ACCESS_TOKEN_SECRET!;
export const refreshTokenSecret = process.env.JWT_REFRESH_TOKEN_SECRET!;
export const accessTokenExpiresIn = process.env.JWT_ACCESS_TOKEN_EXPIRES!; // e.g. "15m"
export const refreshTokenExpiresIn = process.env.JWT_REFRESH_TOKEN_EXPIRES!; // e.g. "7d"
