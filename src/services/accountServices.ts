// src/services/authService.ts
import crypto from 'crypto';
import User from '../models/userModel';
import EncryptData  from '../models/encryptedModel';
import { VirtualCardModel } from '../models/virtualCardModel';
import { generateAccountNumber } from '../utils/generateAccount';
import { generateVirtualCard } from '../utils/generateVirtualCard';
import { RSAUtils } from '../utils/encryption';
import { NotFoundError, BadRequestError } from '../utils/errorClasses';
import { CreateUserRequest} from '../interfaces/userInterface';
import {rsaKeys} from '../config/keys';


if (!rsaKeys.publicKey || !rsaKeys.privateKey) {
  throw new Error('RSA key pair is not configured in environment variables');
}

function hashPhone(phoneNumber: string): string {
  return crypto.createHash('sha256').update(phoneNumber).digest('hex');
}


export async function registerAccount(userData: CreateUserRequest): Promise<any> {
  const { firstName, surname, email, phoneNumber, dateOfBirth } = userData;

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
    phoneNumber: phoneHash,
    accountNumber,
    dateOfBirth
  });

  const encryptedData = new EncryptData({
    userId: user._id,
    cardNumber: encryptedCardNumber,
    cvv: encryptedCVV,
    expiryDate: encryptedExpiryDate,
    phoneNumber: encryptedPhoneNumber,
    dateOfBirth: encryptedDOB,
  });
  await encryptedData.save();

  await VirtualCardModel.create({
    customerId: user._id,
    cardNumber: encryptedCardNumber,
    cvv: encryptedCVV,
    expiryDate: new Date(`${card.expiry}`),
    status: 'ACTIVE',
  });

  // Decrypt data for testing response only
  const decryptedData = {
    cardNumber: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedCardNumber, 'base64')).toString(),
    cvv: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedCVV, 'base64')).toString(),
    expiryDate: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedExpiryDate, 'base64')).toString(),
    phoneNumber: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedPhoneNumber, 'base64')).toString(),
    dateOfBirth: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedDOB, 'base64')).toString(),
  };

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
    encryptedData: {
      cardNumber: encryptedCardNumber,
      cvv: encryptedCVV,
      expiryDate: encryptedExpiryDate,
      phoneNumber: encryptedPhoneNumber,
      dateOfBirth: encryptedDOB,
    },
    decryptedData, // Only included for testing purposes, remove in production
    message: 'Registration successful'
  };
}


export const getAllAccounts = async (): Promise<any> => {
    const users = await User.find({});

    const data = [];

    for (const user of users) {
        const cardDatails= await VirtualCardModel.findOne({ customerId: user._id });
        const encryptedData = await EncryptData.findOne({ userId: user._id });
        if (!cardDatails || !encryptedData) {
            throw new NotFoundError('Card or encrypted data not found');
        }
        const userData = {
            userId: user._id,
            fullName: `${user.firstName} ${user.surname}`,
            accountNumber: user.accountNumber,
        }
        const decryptedData = {
            userId: cardDatails.customerId,
            cardNumber: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedData.cardNumber, 'base64')).toString(),
            cvv: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedData.cvv, 'base64')).toString(),
            expiryDate: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedData.expiryDate, 'base64')).toString(),
            phoneNumber: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedData.phoneNumber, 'base64')).toString(),
            dateOfBirth: RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedData.dateOfBirth, 'base64')).toString(),
        }

        data.push({
            userDate:userData,
            decryptedData:decryptedData,
            encryptedData,
        });
    }

    return data;

}
