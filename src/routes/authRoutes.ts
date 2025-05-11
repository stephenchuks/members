// src/routes/authRoutes.ts
import { Router } from 'express';
import {
  register,
  login,
  refreshToken,
  logout,
} from '../controllers/authController.js';
import { authenticate } from '../middleware/auth.js';
import { asyncHandler } from '../middleware/asyncHandler.js';

const router = Router();

router.post('/register', asyncHandler(register));
router.post('/login', asyncHandler(login));
router.post('/refresh', asyncHandler(refreshToken));
// logout requires valid access token
router.post('/logout', authenticate, asyncHandler(logout));

export default router;
