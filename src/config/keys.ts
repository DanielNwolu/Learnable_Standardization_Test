// src/config/keys.ts
import fs from 'fs';
import path from 'path';

export const rsaKeys = {
  publicKey: fs.readFileSync(path.resolve(__dirname, '../../public.pem'), 'utf8'),
  privateKey: fs.readFileSync(path.resolve(__dirname, '../../private.pem'), 'utf8'),
};
