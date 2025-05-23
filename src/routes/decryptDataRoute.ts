import { NextFunction, Request, Response, Router } from 'express';
import { requestLogger } from '../middleware/loggingMiddleware';
import { decryptData } from '../controllers/decryptDataController';


const router = Router();

router.use(requestLogger);
// Route to decrypt sensitive data
router.post('/', decryptData);
export default router;