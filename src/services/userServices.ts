import crypto from 'crypto';
import User from '../models/userModel';
import EncryptData  from '../models/encryptedModel';
import { VirtualCardModel } from '../models/virtualCardModel';
import { generateAccountNumber } from '../utils/generateAccount';
import { generateVirtualCard } from '../utils/generateVirtualCard';
import { RSAUtils } from '../utils/encryption';
import { NotFoundError, BadRequestError } from '../utils/errorClasses';
import { PartialSession } from '../interfaces/authInterface';
import { encodeSession } from '../config/jwt';
import config from '../config/config';
import { CreateUserRequest, UserResponse } from '../interfaces/userInterface';
import {rsaKeys} from '../config/keys';


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
