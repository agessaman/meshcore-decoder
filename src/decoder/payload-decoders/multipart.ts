// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { MultipartPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';
import { getPayloadTypeName } from '../../utils/enum-names';

export class MultipartPayloadDecoder {
  static decode(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): MultipartPayload & { segments?: PayloadSegment[] } | null {
    const segmentOffset = options?.segmentOffset || 0;

    // Firmware Mesh::createMultiAck() / Mesh::onRecvPacket():
    // byte 0 = (remaining << 4) | inner payload type, followed by the inner payload.
    // Firmware ignores multipart payloads of 2 bytes or fewer.
    if (payload.length < 3) {
      const result: MultipartPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.Multipart,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: ['Multipart payload too short (minimum 3 bytes required)'],
        remaining: 0,
        innerType: PayloadType.RawCustom,
        innerData: ''
      };
      if (options?.includeSegments) {
        result.segments = [{
          name: 'Invalid Multipart Data',
          description: 'Multipart payload too short (minimum 3 bytes required)',
          startByte: segmentOffset,
          endByte: segmentOffset + payload.length - 1,
          value: bytesToHex(payload)
        }];
      }
      return result;
    }

    const remaining = payload[0] >> 4;
    const innerType = (payload[0] & 0x0F) as PayloadType;
    const innerBytes = payload.subarray(1);
    const segments: PayloadSegment[] = [];
    const errors: string[] = [];

    if (options?.includeSegments) {
      segments.push({
        name: 'Multipart Header',
        description: `Remaining packets: ${remaining} | Inner type: ${getPayloadTypeName(innerType)} (0x${innerType.toString(16)})`,
        startByte: segmentOffset,
        endByte: segmentOffset,
        value: payload[0].toString(16).padStart(2, '0').toUpperCase()
      });
    }

    const result: MultipartPayload & { segments?: PayloadSegment[] } = {
      type: PayloadType.Multipart,
      version: PayloadVersion.Version1,
      isValid: true,
      remaining,
      innerType,
      innerData: bytesToHex(innerBytes)
    };

    if (innerType === PayloadType.Ack) {
      if (innerBytes.length >= 4) {
        result.ackChecksum = bytesToHex(innerBytes.subarray(0, 4));
        if (options?.includeSegments) {
          segments.push({
            name: 'ACK Checksum',
            description: `Multipart ACK checksum: 0x${result.ackChecksum}`,
            startByte: segmentOffset + 1,
            endByte: segmentOffset + 4,
            value: result.ackChecksum
          });
          if (innerBytes.length > 4) {
            segments.push({
              name: 'Additional Data',
              description: 'Extra data after ACK checksum',
              startByte: segmentOffset + 5,
              endByte: segmentOffset + payload.length - 1,
              value: bytesToHex(innerBytes.subarray(4))
            });
          }
        }
      } else {
        errors.push('Multipart ACK too short (need 4-byte checksum)');
      }
    } else if (options?.includeSegments) {
      segments.push({
        name: 'Inner Payload',
        description: `${getPayloadTypeName(innerType)} payload fragment (${innerBytes.length} bytes)`,
        startByte: segmentOffset + 1,
        endByte: segmentOffset + payload.length - 1,
        value: bytesToHex(innerBytes)
      });
    }

    if (errors.length > 0) {
      result.isValid = false;
      result.errors = errors;
      if (options?.includeSegments && segments.length === 1) {
        segments.push({
          name: 'Inner Payload',
          description: `${getPayloadTypeName(innerType)} payload fragment (${innerBytes.length} bytes)`,
          startByte: segmentOffset + 1,
          endByte: segmentOffset + payload.length - 1,
          value: bytesToHex(innerBytes)
        });
      }
    }

    if (options?.includeSegments) {
      result.segments = segments;
    }

    return result;
  }
}
