import { NextFunction, Request, Response, Router } from 'express';
import { loginUser, registerUser } from '../controllers/authController';
import { requestLogger } from '../middleware/loggingMiddleware';


const router = Router();

router.post('/login',requestLogger, loginUser);

router.post('/register',requestLogger,registerUser)

export default router;
