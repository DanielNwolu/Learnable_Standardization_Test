import { Request, Response, NextFunction } from 'express';
import { NotFoundError} from '../utils/errorClasses';
import { CreateUserRequest} from '../interfaces/userInterface';
import { registerUser, authenticateUser} from '../services/authService';


export const loginUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email, password } = req.body;
        const loginData = await authenticateUser(email, password);
        if (!loginData) {
            throw new NotFoundError('User not found');
        }
        res.status(201).json({
            status: 'success',
            message: "user logged in successfully",
            data: {
                token: loginData.token,
                expires: loginData.expires,
            }
        });

    } catch (error) {
        next(error);
    }
};


export const register = async (
    req: Request<{}, {}, CreateUserRequest>,
    res: Response,
    next: NextFunction
    ): Promise<void> => {
    try {
        const result = await registerUser(req.body);
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