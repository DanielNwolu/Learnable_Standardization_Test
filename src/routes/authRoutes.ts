import {Router } from 'express';
import { loginUser, register } from '../controllers/authController';
import { validateCreateUser, validateLoginUser } from '../middleware/validationMiddleware';

const router = Router();

router.post('/login', validateLoginUser,loginUser);

router.post('/register',validateCreateUser,register)

export default router;
