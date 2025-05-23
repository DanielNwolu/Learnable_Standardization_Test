import { Request, Response, NextFunction } from 'express';
import { NotFoundError} from '../utils/errorClasses';
import { CreateUserRequest} from '../interfaces/userInterface';
import { registerUser, authenticateUser} from '../services/authService';
import { getAllAccounts } from '../services/userServices';


export const getAllUsersAccount = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const users = await getAllAccounts();
        if (!users) {
            throw new NotFoundError('No users found');
        }
        res.status(200).json({
            status: 'success',
            message: "users fetched successfully",
            data: users,
        });
    } catch (error) {
        next(error);
    }
}