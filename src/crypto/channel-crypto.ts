// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { HmacSHA256, AES, mode, pad, enc, lib, SHA256 } from 'crypto-js';
import { DecryptionResult } from '../types/crypto';
import { hexToBytes, bytesToHex } from '../utils/hex';

export class ChannelCrypto {
  /**
   * Verify the MAC and decrypt a channel (GRP_TXT / GRP_DATA) ciphertext.
   * Matches firmware Utils::MACThenDecrypt() with a GroupChannel secret:
   * - the secret is 16 bytes (128-bit channel) or 32 bytes (256-bit channel),
   *   zero-padded to PUB_KEY_SIZE (32) for the HMAC-SHA256 key
   * - the 2-byte MAC is the first 2 bytes of the HMAC over the ciphertext
   * - AES-128 ECB using the first 16 bytes of the secret
   * - ciphertext must be a non-empty multiple of the 16-byte block size
   */
  static decryptChannelPayload(
    ciphertext: string,
    cipherMac: string,
    channelKey: string
  ): { success: true; data: Uint8Array } | { success: false; error: string } {
    try {
      const keyBytes = hexToBytes(channelKey);
      if (keyBytes.length !== 16 && keyBytes.length !== 32) {
        return { success: false, error: 'Channel key must be 16 or 32 bytes' };
      }
      const ciphertextBytes = hexToBytes(ciphertext);
      if (ciphertextBytes.length === 0 || ciphertextBytes.length % 16 !== 0) {
        return { success: false, error: 'Ciphertext is not block-aligned' };
      }
      const macBytes = hexToBytes(cipherMac);

      const channelSecret = new Uint8Array(32);
      channelSecret.set(keyBytes, 0);

      const calculatedMac = HmacSHA256(enc.Hex.parse(ciphertext), enc.Hex.parse(bytesToHex(channelSecret)));
      const calculatedMacBytes = hexToBytes(calculatedMac.toString(enc.Hex));
      if (calculatedMacBytes[0] !== macBytes[0] || calculatedMacBytes[1] !== macBytes[1]) {
        return { success: false, error: 'MAC verification failed' };
      }

      const aesKey = enc.Hex.parse(bytesToHex(keyBytes.subarray(0, 16)));
      const decrypted = AES.decrypt(
        lib.CipherParams.create({ ciphertext: enc.Hex.parse(ciphertext) }),
        aesKey,
        { mode: mode.ECB, padding: pad.NoPadding }
      );
      return { success: true, data: hexToBytes(decrypted.toString(enc.Hex)) };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Decryption failed' };
    }
  }

  /**
   * Decrypt GroupText message using MeshCore algorithm:
   * - HMAC-SHA256 verification with 2-byte MAC
   * - AES-128 ECB decryption
   */
  static decryptGroupTextMessage(
    ciphertext: string,
    cipherMac: string,
    channelKey: string
  ): DecryptionResult {
    try {
      const result = this.decryptChannelPayload(ciphertext, cipherMac, channelKey);
      if (!result.success) {
        return { success: false, error: result.error };
      }
      const decryptedBytes = result.data;
      if (decryptedBytes.length < 5) {
        return { success: false, error: 'Decrypted content too short' };
      }

      // parse MeshCore format: timestamp(4) + flags(1) + message_text
      const timestamp = (decryptedBytes[0] | 
                       (decryptedBytes[1] << 8) | 
                       (decryptedBytes[2] << 16) | 
                       (decryptedBytes[3] << 24)) >>> 0;
      
      const flagsAndAttempt = decryptedBytes[4];
      
      // extract message text with UTF-8 decoding
      const messageBytes = decryptedBytes.slice(5);
      const decoder = new TextDecoder('utf-8');
      let messageText = decoder.decode(messageBytes);
      
      // remove null terminator if present
      const nullIndex = messageText.indexOf('\0');
      if (nullIndex >= 0) {
        messageText = messageText.substring(0, nullIndex);
      }

      // parse sender and message (format: "sender: message")
      const colonIndex = messageText.indexOf(': ');
      let sender: string | undefined;
      let content: string;

      if (colonIndex > 0 && colonIndex < 50) {
        const potentialSender = messageText.substring(0, colonIndex);
        if (!/[:\[\]]/.test(potentialSender)) {
          sender = potentialSender;
          content = messageText.substring(colonIndex + 2);
        } else {
          content = messageText;
        }
      } else {
        content = messageText;
      }

      return {
        success: true,
        data: {
          timestamp,
          flags: flagsAndAttempt,
          txtType: flagsAndAttempt >> 2,
          attempt: flagsAndAttempt & 0x03,
          sender,
          message: content
        }
      };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Decryption failed' };
    }
  }



  /**
   * Calculate MeshCore channel hash from secret key
   * Returns the first byte of SHA256(secret) as hex string
   */
  static decryptGroupData(
    ciphertext: string,
    cipherMac: string,
    channelKey: string
  ): DecryptionResult {
    const result = this.decryptChannelPayload(ciphertext, cipherMac, channelKey);
    if (!result.success) {
      return { success: false, error: result.error };
    }
    const bytes = result.data;
    // firmware BaseChatMesh::onGroupDataRecv(): data_type(uint16 LE) + data_len(1) + data
    if (bytes.length < 3) {
      return { success: false, authenticated: true, error: 'Decrypted group data too short' };
    }
    const dataType = bytes[0] | (bytes[1] << 8);
    const dataLength = bytes[2];
    if (dataLength > bytes.length - 3) {
      return { success: false, authenticated: true, error: `Group data length ${dataLength} exceeds available ${bytes.length - 3} bytes` };
    }
    return {
      success: true,
      data: {
        dataType,
        dataLength,
        data: bytesToHex(bytes.subarray(3, 3 + dataLength))
      }
    };
  }

  static calculateChannelHash(secretKeyHex: string): string {
    const hash = SHA256(enc.Hex.parse(secretKeyHex));
    const hashBytes = hexToBytes(hash.toString(enc.Hex));
    return hashBytes[0].toString(16).padStart(2, '0');
  }

  /**
   * All channel hashes a secret may appear under on air. Firmware hashes the decoded
   * key length in BaseChatMesh::addChannel(), but BaseChatMesh::setChannel() hashes only
   * the first 16 bytes of a 32-byte buffer whose upper half is zero. A zero-padded
   * 32-byte secret is therefore registered under both hashes.
   */
  static calculateChannelHashes(secretKeyHex: string): string[] {
    const hashes = [this.calculateChannelHash(secretKeyHex)];
    if (secretKeyHex.length === 64 && /^0+$/.test(secretKeyHex.slice(32))) {
      const shortHash = this.calculateChannelHash(secretKeyHex.slice(0, 32));
      if (shortHash !== hashes[0]) hashes.push(shortHash);
    }
    return hashes;
  }

}
