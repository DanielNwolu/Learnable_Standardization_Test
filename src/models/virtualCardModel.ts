import mongoose, { Schema, Document } from 'mongoose';
import { VirtualCard, VirtualCardResponse } from "../interfaces/virtualCardInterface";

// Extend the Document type with our VirtualCardResponse interface
export interface VirtualCardDocument extends Omit<VirtualCardResponse, 'id'>, Document {
    customerId: string;
}

// Create the mongoose schema
const virtualCardSchema = new Schema({
    cardNumber: {
        type: String,
        required: true,
        unique: true,
        length: 16
    },
    cvv: {
        type: String,
        required: true,
        length: 3
    },
    expiryDate: {
        type: Date,
        required: true
    },
    customerId: {
        type: String,
        required: true,
        ref: 'User' // Assuming you have a User model
    },
    status: {
        type: String,
        enum: ['ACTIVE', 'INACTIVE', 'EXPIRED'],
        default: 'ACTIVE'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Add indexes for better query performance
virtualCardSchema.index({ customerId: 1 });
virtualCardSchema.index({ cardNumber: 1 }, { unique: true });

// Create and export the model
export const VirtualCardModel = mongoose.model<VirtualCardDocument>('VirtualCard', virtualCardSchema);