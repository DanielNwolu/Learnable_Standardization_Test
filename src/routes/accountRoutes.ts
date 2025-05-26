import {Router } from 'express';
import { register, getAllUsersAccount } from '../controllers/accountControllers';
import { validateCreateUser} from '../middleware/validationMiddleware';

const router = Router();

router.get('/', getAllUsersAccount);
router.post('/register',validateCreateUser,register)


export default router;
