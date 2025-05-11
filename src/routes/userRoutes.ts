// src/routes/userRoutes.ts
import { Router } from 'express';
import { authenticate, authorize } from '../middleware/auth.js';
import { asyncHandler } from '../middleware/asyncHandler.js';
import { getAllUsers } from '../controllers/userController.js';

const router = Router();

router.use(authenticate);
router.get('/', authorize(['admin','superadmin']), asyncHandler(getAllUsers));

export default router;
