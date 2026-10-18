// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { PathPayload, PathPlaintext } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class PathPayloadDecoder {
  static decode(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): PathPayload & { segments?: PayloadSegment[] } | null {
    try {
      // Firmware Mesh::createPathReturn() / Mesh::onRecvPacket():
      // - destination hash (1 byte)
      // - source hash (1 byte)
      // - cipher MAC (2 bytes)
      // - ciphertext (rest of payload), encrypted: path_len(1) + path + extra_type(1) + extra
      // Firmware requires at least one byte of ciphertext after the MAC.

      if (payload.length < 5) {
        const result: PathPayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.Path,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Path payload too short (minimum 5 bytes: dest + source + MAC + ciphertext)'],
          destinationHash: '',
          sourceHash: '',
          cipherMac: '',
          ciphertext: '',
          ciphertextLength: 0
        };

        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid Path Data',
            description: 'Path payload too short (minimum 5 bytes required)',
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

      const destinationHash = byteToHex(payload[offset]);
      if (options?.includeSegments) {
        segments.push({
          name: 'Destination Hash',
          description: 'First byte of destination node public key',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: destinationHash
        });
      }
      offset += 1;

      const sourceHash = byteToHex(payload[offset]);
      if (options?.includeSegments) {
        segments.push({
          name: 'Source Hash',
          description: 'First byte of source node public key',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: sourceHash
        });
      }
      offset += 1;

      const cipherMac = bytesToHex(payload.subarray(offset, offset + 2));
      if (options?.includeSegments) {
        segments.push({
          name: 'Cipher MAC',
          description: 'MAC for encrypted data in next field',
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
          description: `Encrypted returned path (${payload.length - offset} bytes). Contains encrypted plaintext with this structure:
• Path Length (1 byte) - bits 7:6 = hash size - 1, bits 5:0 = hop count
• Path (hop count × hash size bytes) - route from the original sender to this node
• Extra Type (1 byte) - lower 4 bits: bundled payload type (e.g. ACK or RESPONSE, 0x0F = none)
• Extra (remaining bytes) - bundled payload content`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + payload.length - 1,
          value: ciphertext
        });
      }

      const result: PathPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.Path,
        version: PayloadVersion.Version1,
        isValid: true,
        destinationHash,
        sourceHash,
        cipherMac,
        ciphertext,
        ciphertextLength: payload.length - 4
      };

      if (options?.includeSegments) {
        result.segments = segments;
      }

      return result;
    } catch (error) {
      return {
        type: PayloadType.Path,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode Path payload'],
        destinationHash: '',
        sourceHash: '',
        cipherMac: '',
        ciphertext: '',
        ciphertextLength: 0
      };
    }
  }

  /**
   * Parse the decrypted plaintext of a PATH payload.
   * Firmware reference: Mesh::onRecvPacket() PAYLOAD_TYPE_PATH branch.
   * Returns null if the encoding is invalid (reserved hash size, path longer
   * than 64 bytes, or truncated data).
   */
  static parsePlaintext(data: Uint8Array): PathPlaintext | null {
    if (data.length < 2) return null;

    const pathLenByte = data[0];
    const pathHashSize = (pathLenByte >> 6) + 1;
    const pathHopCount = pathLenByte & 63;
    const pathByteLength = pathHopCount * pathHashSize;

    // Packet::isValidPathLen()
    if (pathHashSize === 4 || pathByteLength > 64) return null;
    if (data.length < 1 + pathByteLength + 1) return null;

    const pathHashes: string[] = [];
    for (let i = 0; i < pathHopCount; i++) {
      const start = 1 + i * pathHashSize;
      pathHashes.push(bytesToHex(data.subarray(start, start + pathHashSize)));
    }

    const extraType = data[1 + pathByteLength] & 0x0F; // upper 4 bits reserved
    const extraData = bytesToHex(data.subarray(1 + pathByteLength + 1));

    return {
      pathLength: pathHopCount,
      pathHashSize,
      pathHashes,
      extraType,
      extraData
    };
  }
}
