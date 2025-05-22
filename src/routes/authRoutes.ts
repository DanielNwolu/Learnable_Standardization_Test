import { NextFunction, Request, Response, Router } from 'express';
import { loginUser, register } from '../controllers/authController';
import { requestLogger } from '../middleware/loggingMiddleware';
import { validateCreateUser, validateLoginUser } from '../middleware/validationMiddleware';

const router = Router();

// Middleware to log request details
router.use(requestLogger);

router.post('/login', validateLoginUser,loginUser);

router.post('/register',validateCreateUser,register)

export default router;
