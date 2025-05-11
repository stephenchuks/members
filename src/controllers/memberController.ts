// src/controllers/memberController.ts
import type { RequestHandler } from 'express';
import { DbService } from '../services/dbService.js';
import Member, { IMember } from '../models/Member.js';
import { clearCache } from '../utils/cache.js';

const memberService = new DbService<IMember>(Member);

export const createMember: RequestHandler = async (req, res, next): Promise<void> => {
  try {
    const m = await memberService.create(req.body as Partial<IMember>);
    await clearCache('members:list');
    res.status(201).json(m);
  } catch (err) {
    next(err);
  }
};

export const listMembers: RequestHandler = async (req, res, next): Promise<void> => {
  try {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const filter: any = {};
    if (req.query.status) filter.status = req.query.status;
    const skip = (page - 1) * limit;
    const { total, data } = await memberService.findAll(filter, { skip, limit, sort: { createdAt: -1 } });
    res.json({
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
      data,
    });
  } catch (err) {
    next(err);
  }
};

export const getMemberById: RequestHandler = async (req, res, next): Promise<void> => {
  try {
    const m = await memberService.findById(req.params.id);
    if (!m) {
      res.status(404).json({ message: 'Not Found' });
      return;
    }
    res.json(m);
  } catch (err) {
    next(err);
  }
};

export const updateMember: RequestHandler = async (req, res, next): Promise<void> => {
  try {
    const m = await memberService.update(req.params.id, req.body);
    if (!m) {
      res.status(404).json({ message: 'Not Found' });
      return;
    }
    await clearCache('members:list');
    res.json(m);
  } catch (err) {
    next(err);
  }
};

export const deleteMember: RequestHandler = async (req, res, next): Promise<void> => {
  try {
    const m = await memberService.delete(req.params.id);
    if (!m) {
      res.status(404).json({ message: 'Not Found' });
      return;
    }
    await clearCache('members:list');
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};
