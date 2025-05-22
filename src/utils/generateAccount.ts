import { randomUUID } from 'crypto';
import { createHash } from 'crypto';

/**
 * Generates a unique 10-digit numeric account number by hashing a UUID.
 * Ensures low collision probability and consistent format.
 *
 * @returns {string} 10-digit unique account number
 */
export function generateAccountNumber(): string {
  const uuid = randomUUID();
  const hash = createHash('sha256').update(uuid).digest('hex');
  const numericHash = hash.replace(/\D/g, '');

  if (numericHash.length < 10) {
    throw new Error('Insufficient numeric data in hash to generate account number');
  }

  return numericHash.slice(0, 10);
}
