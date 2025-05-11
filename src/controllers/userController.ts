// src/controllers/userController.ts
import { RequestHandler } from 'express';
import User from '../models/User.js';

/** GET /api/users
 *  Admin-only: returns all users without passwords
 */
export const getAllUsers: RequestHandler = async (_req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};
