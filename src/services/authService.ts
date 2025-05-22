// src/services/authService.ts
import crypto from 'crypto';
import User from '../models/userModel';
import { VirtualCardModel } from '../models/virtualCardModel';
import { generateAccountNumber } from '../utils/generateAccount';
import { generateVirtualCard } from '../utils/generateVirtualCard';
import { RSAUtils } from '../utils/encryption';
import settings from '../config/config';
import { NotFoundError, BadRequestError } from '../utils/errorClasses';
import { PartialSession } from '../interfaces/authInterface';
import { encodeSession } from '../config/jwt';
import config from '../config/config';
import { CreateUserRequest, UserResponse } from '../interfaces/userInterface';
import {rsaKeys} from '../config/keys';

if (!rsaKeys.publicKey || !rsaKeys.privateKey) {
  throw new Error('RSA key pair is not configured in environment variables');
}

function hashPhone(phoneNumber: string): string {
  return crypto.createHash('sha256').update(phoneNumber).digest('hex');
}

export async function registerUser(userData: CreateUserRequest): Promise<any> {
  const { firstName, surname, email, phoneNumber, dateOfBirth, password } = userData;

  const phoneHash = hashPhone(phoneNumber);

  // Check if the user already exists
  const existingUser = await User.findOne({
    $or: [
      { email },
      { phoneHash },
    ],
  });

  if (existingUser) {
    throw new BadRequestError('User already exists with this email or phone number');
  }

  const accountNumber = generateAccountNumber();
  const card = generateVirtualCard();

  const encryptedCardNumber = RSAUtils.encrypt(rsaKeys.publicKey, card.cardNumber).toString('base64');
  const encryptedCVV = RSAUtils.encrypt(rsaKeys.publicKey, card.cvv).toString('base64');
  const encryptedExpiryDate = RSAUtils.encrypt(rsaKeys.publicKey, card.expiry).toString('base64');
  const encryptedPhoneNumber = RSAUtils.encrypt(rsaKeys.publicKey, phoneNumber).toString('base64');
  const encryptedDOB = RSAUtils.encrypt(rsaKeys.publicKey, dateOfBirth.toString()).toString('base64');

  const user = await User.create({
    firstName,
    surname,
    email,
    phoneNumber: encryptedPhoneNumber,
    phoneHash,
    dateOfBirth: encryptedDOB,
    password,
    accountNumber,
  });

  await VirtualCardModel.create({
    customerId: user._id,
    cardNumber: encryptedCardNumber,
    cvv: encryptedCVV,
    expiryDate: new Date(`${card.expiry}`),
    status: 'ACTIVE',
  });

  return {
    user: {
      _id: user._id,
      firstName: user.firstName,
      surname: user.surname,
      email: user.email,
      accountNumber: user.accountNumber,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    },
    message: 'Registration successful'
  };
}

export async function loginUser(email: string, password: string): Promise<UserResponse | null> {
  const user = await User.findOne({ email });
  if (!user) return null;
  const isMatch = await user.comparePassword(password);
  if (!isMatch) return null;

  return {
    _id: user._id,
    firstName: user.firstName,
    surname: user.surname,
    email: user.email,
    phoneNumber: user.phoneNumber,
    dateOfBirth: user.dateOfBirth,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

export async function authenticateUser(email: string, password: string): Promise<{ user: UserResponse; token: string; expires: number }> {
  if (!email || !password) {
    throw new BadRequestError('Email and password are required');
  }

  const user = await User.findOne({ email });
  if (!user) {
    throw new NotFoundError('User not found');
  }

  const isPasswordValid = await user.comparePassword(password);
  if (!isPasswordValid) {
    throw new BadRequestError('Invalid email or password');
  }

  const session: PartialSession = {
    id: user.id,
    firstName: user.firstName,
    email: user.email,
    dateCreated: Date.now(),
  };

  const { token, expires } = encodeSession(config.jwt.access_token, session);

  return {
    user: {
      _id: user._id,
      firstName: user.firstName,
      surname: user.surname,
      email: user.email,
      phoneNumber: user.phoneNumber,
      dateOfBirth: user.dateOfBirth,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    },
    token,
    expires,
  };
}
