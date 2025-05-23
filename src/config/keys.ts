const publicKey = (process.env.RSA_PUBLIC ?? '').replace(/\\n/g, '\n');
const privateKey = (process.env.RSA_PRIVATE ?? '').replace(/\\n/g, '\n');

export const rsaKeys = {
  publicKey,
  privateKey
};
