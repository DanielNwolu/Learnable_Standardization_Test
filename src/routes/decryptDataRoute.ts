import {Router } from 'express';
import { decryptData } from '../controllers/decryptDataController';
import { validateDecrypt } from '../middleware/validationMiddleware';


const router = Router();

// Route to decrypt sensitive data
router.post('/',validateDecrypt,decryptData);
export default router;