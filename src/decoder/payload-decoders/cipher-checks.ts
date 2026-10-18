// firmware MeshCore.h CIPHER_BLOCK_SIZE
const CIPHER_BLOCK_SIZE = 16;

/**
 * Firmware Utils::MACThenDecrypt() rejects ciphertext that is not a multiple of the
 * AES block size, so such payloads can never be decrypted by a node.
 */
export function cipherBlockError(ciphertextLength: number): string | undefined {
  if (ciphertextLength % CIPHER_BLOCK_SIZE === 0) return undefined;
  return `Ciphertext length ${ciphertextLength} is not a multiple of the ${CIPHER_BLOCK_SIZE}-byte AES block`;
}
