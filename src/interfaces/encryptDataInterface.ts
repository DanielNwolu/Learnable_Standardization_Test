import { Document } from 'mongoose';

export interface EncryptDataInterface extends Document {
    _id: string;
    userId: string;
    cardNumber: string;
    cvv: string;
    expiryDate: string;
    phoneNumber: string;
    dateOfBirth: string;
    createdAt: Date;
    updatedAt: Date;
}

export interface EncryptDataCreationRequest {
    userId: string;
    cardNumber: string;
    cvv: string;
    expiryDate: string;
    phoneNumber: string;
    dateOfBirth: string;
}
