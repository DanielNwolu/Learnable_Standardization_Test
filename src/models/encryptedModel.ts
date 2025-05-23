import mongoose, { Schema } from 'mongoose';
import {EncryptDataInterface  } from '../interfaces/encryptDataInterface';


const encryptDataSchema = new Schema<EncryptDataInterface>({
    userId: {
        type: String,
        ref: 'User',
        required: true,
    },
    cardNumber: {
        type: String,
        required: true,
    },
    cvv: {
        type: String,
        required: true,
    },
    expiryDate: {
        type: String,
        required: true,
    },
    phoneNumber: {
        type: String,
        required: true,
    },
    dateOfBirth: {
        type: String,
        required: true,
    },
}, { timestamps: true });
const EncryptData = mongoose.model<EncryptDataInterface>('EncryptData', encryptDataSchema);
export default EncryptData;
