import { randomUUID } from 'crypto';
import { createHash, randomInt } from 'crypto';

/**
 * Generates a random 6-digit BIN (Bank Identification Number).
 * Note: This is for testing purposes only.
 */
function generateTestBIN(): string {
  return Array.from({ length: 6 }, () => randomInt(0, 10)).join('');
}

export function generateVirtualCard() {
  const BIN = generateTestBIN();

  const uuid = randomUUID();
  const hash = createHash('sha256').update(uuid).digest('hex');
  const digits = hash.replace(/\D/g, '');

  if (digits.length < 9) {
    throw new Error('Unable to generate sufficient digits for card number');
  }

  const accountPart = digits.slice(0, 9);
  const partialCard = BIN + accountPart;

  // Calculate Luhn checksum
  const luhnChecksum = (input: string): string => {
    const sum = input
      .split('')
      .reverse()
      .map((d, i) => {
        let n = parseInt(d);
        if (i % 2 === 0) n *= 2;
        return n > 9 ? n - 9 : n;
      })
      .reduce((acc, val) => acc + val, 0);
    return ((10 - (sum % 10)) % 10).toString();
  };

  const cardNumber = partialCard + luhnChecksum(partialCard);

  const cvv = randomInt(100, 1000).toString();

  const now = new Date();
  now.setFullYear(now.getFullYear() + 3);
  const expiry = `${String(now.getMonth() + 1).padStart(2, '0')}/${String(now.getFullYear()).slice(-2)}`;

  return { cardNumber, cvv, expiry };
}