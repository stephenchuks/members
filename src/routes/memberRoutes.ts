// src/routes/memberRoutes.ts
import { Router } from 'express';
import { asyncHandler } from '../middleware/asyncHandler.js';
import { authenticate, authorize } from '../middleware/auth.js';
import {
  createMember,
  listMembers,
  getMemberById,
  updateMember,
  deleteMember,
} from '../controllers/memberController.js';

const router = Router();

// all member routes require authentication
router.use(authenticate);

// Admin-only:
router.post('/', authorize(['admin', 'superadmin']), asyncHandler(createMember));
router.get('/', authorize(['admin']), asyncHandler(listMembers));
router.get('/:id', authorize(['admin']), asyncHandler(getMemberById));
router.put('/:id', authorize(['admin']), asyncHandler(updateMember));
router.delete('/:id', authorize(['admin']), asyncHandler(deleteMember));

// “Me” endpoint for users:
router.get(
  '/me',
  authorize(['user', 'admin', 'superadmin']),
  asyncHandler(async (req, res) => {
    const meId = (req as any).user.userId;
    const m = await (await import('../models/Member.js')).default.findById(meId).exec();
    if (!m) return res.status(404).json({ message: 'Not Found' });
    res.json(m);
  })
);

export default router;
