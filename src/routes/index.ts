// src/routes/index.ts
import { Router, RequestHandler } from 'express';

const router = Router();

const health: RequestHandler = (_req, res) => {
  res.sendStatus(200);
};

const docsStub: RequestHandler = (_req, res) => {
  res.status(501).json({ message: 'Swagger not set up yet' });
};

router.get('/health', health);
router.get('/docs', docsStub);

export default router;
