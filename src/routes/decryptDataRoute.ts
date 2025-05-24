import {Router } from 'express';
import { decryptData } from '../controllers/decryptDataController';


const router = Router();

// Route to decrypt sensitive data
router.post('/', decryptData);
export default router;