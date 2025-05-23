import {rsaKeys} from '../config/keys';
import { RSAUtils } from '../utils/encryption';
import { BadRequestError } from '../utils/errorClasses';

// route services that decrypts sensitive data


export const decryptSensitiveData = async (encryptedData:string): Promise<string> => {
    if (!rsaKeys.publicKey || !rsaKeys.privateKey) {
        throw new Error('RSA key pair is not configured in environment variables');
    }

    const decryptedData = RSAUtils.decrypt(rsaKeys.privateKey, Buffer.from(encryptedData, 'base64')).toString();
    if (!decryptedData) {
        throw new BadRequestError('Decryption failed, data may be corrupted or invalid');
    }
    return decryptedData;
}