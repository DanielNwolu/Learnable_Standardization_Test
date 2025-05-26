import { Document } from 'mongoose';

export interface User extends Document {
    _id: string;
    firstName: string;
    surname: string;
    email: string;
    phoneNumber: string;
    dateOfBirth: Date;
    accountNumber: string; // 10-digit number
    createdAt: Date;
    updatedAt: Date;
    comparePassword(candidatePassword: string): Promise<boolean>;
}

// for user creation validation
export interface CreateUserRequest {
    firstName: string;
    surname: string;
    email: string;
    phoneNumber: string;
    dateOfBirth: Date;
}

// for user update validation
export interface UpdateUserRequest {
    firstName?: string;
    surname?: string;
    email?: string;
    phoneNumber?: string;
    dateOfBirth?: Date;
}

// for user response
export interface UserResponse {
    _id: string;
    firstName: string;
    surname: string;
    email: string;
    phoneNumber: string;
    dateOfBirth: Date;
    createdAt: Date;
    updatedAt: Date;
}