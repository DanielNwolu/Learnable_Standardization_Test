import { Request, Response, NextFunction } from 'express';
import { decryptSensitiveData } from '../services/decryptServices';

export const decryptData = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { encryptedData } = req.body;
        const decryptedData = await decryptSensitiveData(encryptedData);
        res.status(200).json({
            status: 'success',
            message: 'Decryption successful',
            data: decryptedData,
        });
    } catch (error) {
        next(error);
    }
};