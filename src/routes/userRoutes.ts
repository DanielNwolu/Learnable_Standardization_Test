import { NextFunction, Request, Response, Router } from 'express';
import { getAllUsersAccount } from '../controllers/userController';
import { requestLogger } from '../middleware/loggingMiddleware';
import { validateCreateUser, validateLoginUser } from '../middleware/validationMiddleware';
import { requireJwtMiddleware } from '../middleware/authMiddleware';

const router = Router();

router.use(requestLogger);

router.get('/', requireJwtMiddleware,getAllUsersAccount);

export default router;