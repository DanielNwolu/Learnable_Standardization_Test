import { Request, Response, NextFunction } from 'express';
import { NotFoundError} from '../utils/errorClasses';
import { CreateUserRequest} from '../interfaces/userInterface';
import { registerAccount , getAllAccounts} from '../services/accountServices';


export const register = async (
    req: Request<{}, {}, CreateUserRequest>,
    res: Response,
    next: NextFunction
    ): Promise<void> => {
    try {
        const result = await registerAccount(req.body);
        // Create a new user in the database
        res.status(201).json({
        status: 'success',
        message: "user created successfully",
        data: result,
        });
    } catch (error) {
        next(error);
    }
};


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