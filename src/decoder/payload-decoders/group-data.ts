// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { GroupDataPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { cipherBlockError } from './cipher-checks';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { DecryptionOptions } from '../../types/crypto';
import { ChannelCrypto } from '../../crypto/channel-crypto';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class GroupDataPayloadDecoder {
  static decode(payload: Uint8Array, options?: DecryptionOptions & { includeSegments?: boolean; segmentOffset?: number }): GroupDataPayload & { segments?: PayloadSegment[] } | null {
    try {
      // Same envelope as GRP_TXT: channel_hash(1) + MAC(2) + ciphertext.
      // Firmware requires at least one byte of ciphertext after the MAC.
      if (payload.length < 4) {
        const result: GroupDataPayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.GroupData,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['GroupData payload too short (need at least channel_hash(1) + MAC(2) + ciphertext)'],
          channelHash: '',
          cipherMac: '',
          ciphertext: '',
          ciphertextLength: 0
        };

        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid GroupData Data',
            description: 'GroupData payload too short (minimum 4 bytes required)',
            startByte: options.segmentOffset || 0,
            endByte: (options.segmentOffset || 0) + payload.length - 1,
            value: bytesToHex(payload)
          }];
        }

        return result;
      }

      const segments: PayloadSegment[] = [];
      const segmentOffset = options?.segmentOffset || 0;
      let offset = 0;

      const channelHash = byteToHex(payload[offset]);
      if (options?.includeSegments) {
        segments.push({
          name: 'Channel Hash',
          description: 'First byte of SHA256 of channel\'s shared key',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: channelHash
        });
      }
      offset += 1;

      const cipherMac = bytesToHex(payload.subarray(offset, offset + 2));
      if (options?.includeSegments) {
        segments.push({
          name: 'Cipher MAC',
          description: 'MAC for encrypted data',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset + 1,
          value: cipherMac
        });
      }
      offset += 2;

      const ciphertext = bytesToHex(payload.subarray(offset));
      if (options?.includeSegments) {
        segments.push({
          name: 'Ciphertext',
          description: 'Encrypted datagram (data type (2 bytes, LE) + data length (1 byte) + data)',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + payload.length - 1,
          value: ciphertext
        });
      }

      const blockError = cipherBlockError(payload.length - offset);
      const groupData: GroupDataPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.GroupData,
        version: PayloadVersion.Version1,
        isValid: !blockError,
        ...(blockError ? { errors: [blockError] } : {}),
        channelHash,
        cipherMac,
        ciphertext,
        ciphertextLength: payload.length - 3
      };

      if (options?.keyStore && options.keyStore.hasChannelKey(channelHash)) {
        for (const channelKey of options.keyStore.getChannelKeys(channelHash)) {
          const decryptionResult = ChannelCrypto.decryptGroupData(ciphertext, cipherMac, channelKey);
          if (decryptionResult.success && decryptionResult.data) {
            groupData.decrypted = decryptionResult.data;
            break;
          }
        }
      }

      if (options?.includeSegments) {
        groupData.segments = segments;
      }

      return groupData;
    } catch (error) {
      return {
        type: PayloadType.GroupData,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode GroupData payload'],
        channelHash: '',
        cipherMac: '',
        ciphertext: '',
        ciphertextLength: 0
      };
    }
  }
}
