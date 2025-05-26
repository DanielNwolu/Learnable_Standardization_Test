import { Request, Response, NextFunction } from 'express';
import { BadRequestError } from '../utils/errorClasses';
import Joi from 'joi';

// Generic validation middleware
export function validateRequest<T>(validator: (data: any) => { valid: boolean; errors: string[] }) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const { valid, errors } = validator(req.body);
    
    if (!valid) {
      return next(new BadRequestError(`Validation error: ${errors.join(', ')}`));
    }
    
    next();
  };
}

// Example validation schema for user creation
const createUserSchema = Joi.object({
  firstName: Joi.string().required(),
  surname: Joi.string().required(),
  email: Joi.string().email().required(),
  phoneNumber: Joi.string().pattern(/^[0-9]{10,}$/).required(), // at least 10 digits
  dateOfBirth: Joi.date().iso().required(),
});
// Example validation function for user creation
export const validateCreateUser = (req: Request, res: Response, next: NextFunction) => {
  const { error } = createUserSchema.validate(req.body);
  if (error) {
    return next(new BadRequestError(`Validation error: ${error.details.map(detail => detail.message).join(', ')}`));
  }
  next();
};

// Validation schema for decryption
const decryptSchema = Joi.object({
  encryptedData: Joi.string().required().base64()
});

// Validation function for decryption
export const validateDecrypt = (req: Request, _: Response, next: NextFunction) => {
  const { error } = decryptSchema.validate(req.body);
  if (error) {
    return next(new BadRequestError(`Validation error: ${error.details.map(detail => detail.message).join(', ')}`));
  }
  next();
};



