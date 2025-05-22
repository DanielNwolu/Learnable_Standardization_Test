// src/config/keys.ts
import fs from 'fs';
import path from 'path';

export const rsaKeys = {
  publicKey: fs.readFileSync(path.resolve(__dirname, '../../rsa_public.pem'), 'utf8'),
  privateKey: fs.readFileSync(path.resolve(__dirname, '../../rsa_private.pem'), 'utf8'),
};
