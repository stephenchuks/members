// src/middleware/error.ts
import type { Request, Response, NextFunction } from 'express';

/** 404 handler */
export const notFound = (req: Request, res: Response, next: NextFunction) => {
  res.status(404).json({ message: `Not Found – ${req.originalUrl}` });
};

/** Global error handler */
export const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.error(err.stack);
  const status = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  res.status(status).json({ message });
};
