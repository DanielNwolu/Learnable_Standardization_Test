import {Router } from 'express';
import { getAllUsersAccount } from '../controllers/userController';
import { requireJwtMiddleware } from '../middleware/authMiddleware';

const router = Router();

router.get('/', requireJwtMiddleware,getAllUsersAccount);

export default router;