import * as crypto from 'crypto';

interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export class RSAUtils {
  /**
   * Generate an RSA key pair
   * @returns Promise resolving to an object containing publicKey and privateKey
   */
  static generateKeyPair(): Promise<KeyPair> {
    return new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        'rsa',
        {
          modulusLength: 2048,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc', // Optional: encrypt the private key
            passphrase: '',        // Optional: supply your own passphrase
          },
        },
        (err, publicKey, privateKey) => {
          if (err) return reject(err);
          resolve({ publicKey, privateKey });
        }
      );
    });
  }

  /**
   * Encrypts data using RSA public key
   */
  static encrypt(publicKey: string, plaintext: string): Buffer {
    return crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(plaintext)
    );
  }

  /**
   * Decrypts RSA encrypted data using private key
   */
  static decrypt(privateKey: string, encrypted: Buffer): Buffer {
    return crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encrypted
    );
  }

  /**
   * Signs a message with private key
   */
  static sign(privateKey: string, message: string): string {
    const signer = crypto.createSign('sha256');
    signer.update(message);
    signer.end();
    return signer.sign(privateKey, 'base64');
  }

  /**
   * Verifies a signed message with public key
   */
  static verify(publicKey: string, message: string, signature: string): boolean {
    const verifier = crypto.createVerify('sha256');
    verifier.update(message);
    verifier.end();
    return verifier.verify(publicKey, signature, 'base64');
  }
}
