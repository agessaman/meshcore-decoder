// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { AdvertPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion, DeviceRole, AdvertFlags } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';
import { getDeviceRoleName } from '../../utils/enum-names';
import { Ed25519SignatureVerifier } from '../../crypto/ed25519-verifier';

// firmware MeshCore.h MAX_ADVERT_DATA_SIZE
const MAX_ADVERT_DATA_SIZE = 32;
// public_key(32) + timestamp(4) + signature(64)
const APP_DATA_START = 100;

export class AdvertPayloadDecoder {
  static decode(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): AdvertPayload & { segments?: PayloadSegment[] } | null {
    try {
      // start of appdata section: public_key(32) + timestamp(4) + signature(64) + flags(1) = 101 bytes.
      // Mesh::onRecvPacket() accepts 100 bytes, but AdvertDataParser then has no flags byte to read,
      // so an advert without app data is treated as invalid here.
      if (payload.length < 101) {
        const result: AdvertPayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.Advert,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Advertisement payload too short'],
          publicKey: '',
          timestamp: 0,
          signature: '',
          appData: {
            flags: 0,
            deviceRole: DeviceRole.Unknown,
            hasLocation: false,
            hasName: false,
            hasFeature1: false,
            hasFeature2: false
          }
        };
        
        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid Advert Data',
            description: 'Advert payload too short (minimum 101 bytes required)',
            startByte: options.segmentOffset || 0,
            endByte: (options.segmentOffset || 0) + payload.length - 1,
            value: bytesToHex(payload)
          }];
        }
        
        return result;
      }

      const segments: PayloadSegment[] = [];
      const segmentOffset = options?.segmentOffset || 0;
      let currentOffset = 0;

      // parse advertisement structure from payloads.md
      const publicKey = bytesToHex(payload.subarray(currentOffset, currentOffset + 32));
      if (options?.includeSegments) {
        segments.push({
          name: 'Public Key',
          description: 'Ed25519 public key',
          startByte: segmentOffset + currentOffset,
          endByte: segmentOffset + currentOffset + 31,
          value: publicKey
        });
      }
      currentOffset += 32;
      
      const timestamp = this.readUint32LE(payload, currentOffset);
      if (options?.includeSegments) {
        const timestampDate = new Date(timestamp * 1000);
        segments.push({
          name: 'Timestamp',
          description: `${timestamp} (${timestampDate.toISOString().slice(0, 19)}Z)`,
          startByte: segmentOffset + currentOffset,
          endByte: segmentOffset + currentOffset + 3,
          value: bytesToHex(payload.subarray(currentOffset, currentOffset + 4))
        });
      }
      currentOffset += 4;
      
      const signature = bytesToHex(payload.subarray(currentOffset, currentOffset + 64));
      if (options?.includeSegments) {
        segments.push({
          name: 'Signature',
          description: 'Ed25519 signature',
          startByte: segmentOffset + currentOffset,
          endByte: segmentOffset + currentOffset + 63,
          value: signature
        });
      }
      currentOffset += 64;
      
      const flags = payload[currentOffset];
      if (options?.includeSegments) {
        const binaryStr = flags.toString(2).padStart(8, '0');
        const deviceRole = this.parseDeviceRole(flags);
        const roleName = getDeviceRoleName(deviceRole);
        const yn = (mask: number) => (flags & mask) ? 'Yes' : 'No';
        const flagDesc = ` | Bits 0-3 (Role): ${roleName} | Bit 4 (Location): ${yn(AdvertFlags.HasLocation)} | Bit 5 (Feature 1): ${yn(AdvertFlags.HasFeature1)} | Bit 6 (Feature 2): ${yn(AdvertFlags.HasFeature2)} | Bit 7 (Name): ${yn(AdvertFlags.HasName)}`;
        segments.push({
          name: 'App Flags',
          description: `Binary: ${binaryStr}${flagDesc}`,
          startByte: segmentOffset + currentOffset,
          endByte: segmentOffset + currentOffset,
          value: flags.toString(16).padStart(2, '0').toUpperCase()
        });
      }
      currentOffset += 1;

      const advert: AdvertPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.Advert,
        version: PayloadVersion.Version1,
        isValid: true,
        publicKey,
        timestamp,
        signature,
        appData: {
          flags,
          deviceRole: this.parseDeviceRole(flags),
          hasLocation: !!(flags & AdvertFlags.HasLocation),
          hasName: !!(flags & AdvertFlags.HasName),
          hasFeature1: !!(flags & AdvertFlags.HasFeature1),
          hasFeature2: !!(flags & AdvertFlags.HasFeature2)
        }
      };
      const appDataErrors: string[] = [];

      let offset = currentOffset;

      // optional fields in firmware AdvertDataParser order: lat/lon, feature 1, feature 2
      if (flags & AdvertFlags.HasLocation) {
        if (payload.length >= offset + 8) {
          const lat = this.readInt32LE(payload, offset) / 1000000;
          const lon = this.readInt32LE(payload, offset + 4) / 1000000;
          advert.appData.location = {
            latitude: Math.round(lat * 1000000) / 1000000,
            longitude: Math.round(lon * 1000000) / 1000000
          };

          if (options?.includeSegments) {
            segments.push({
              name: 'Latitude',
              description: `${lat}° (${lat})`,
              startByte: segmentOffset + offset,
              endByte: segmentOffset + offset + 3,
              value: bytesToHex(payload.subarray(offset, offset + 4))
            });

            segments.push({
              name: 'Longitude',
              description: `${lon}° (${lon})`,
              startByte: segmentOffset + offset + 4,
              endByte: segmentOffset + offset + 7,
              value: bytesToHex(payload.subarray(offset + 4, offset + 8))
            });
          }
        } else {
          appDataErrors.push('App data too short for location');
        }
        offset += 8;
      }

      for (const [mask, key, label] of [
        [AdvertFlags.HasFeature1, 'feature1', 'Feature 1'],
        [AdvertFlags.HasFeature2, 'feature2', 'Feature 2']
      ] as const) {
        if (!(flags & mask)) continue;
        if (payload.length >= offset + 2) {
          const value = payload[offset] | (payload[offset + 1] << 8);
          advert.appData[key] = value;
          if (options?.includeSegments) {
            segments.push({
              name: label,
              description: `Reserved for future use: ${value} (0x${value.toString(16).padStart(4, '0')})`,
              startByte: segmentOffset + offset,
              endByte: segmentOffset + offset + 1,
              value: bytesToHex(payload.subarray(offset, offset + 2))
            });
          }
        } else {
          appDataErrors.push(`App data too short for ${label.toLowerCase()}`);
        }
        offset += 2;
      }

      if (appDataErrors.length > 0) {
        advert.isValid = false;
        advert.errors = appDataErrors;
      }

      // name data (if HasName flag is set); firmware caps app_data at
      // MAX_ADVERT_DATA_SIZE bytes, so anything beyond that is not part of the name
      const appDataEnd = Math.min(payload.length, APP_DATA_START + MAX_ADVERT_DATA_SIZE);
      if (flags & AdvertFlags.HasName && appDataEnd > offset) {
        const nameBytes = payload.subarray(offset, appDataEnd);
        const rawName = new TextDecoder('utf-8').decode(nameBytes).replace(/\0[\s\S]*$/, '');
        advert.appData.name = this.sanitizeControlCharacters(rawName) || rawName;
        
        if (options?.includeSegments) {
          segments.push({
            name: 'Node Name',
            description: `Node name: "${advert.appData.name}"`,
            startByte: segmentOffset + offset,
            endByte: segmentOffset + appDataEnd - 1,
            value: bytesToHex(nameBytes)
          });
        }
      }

      if (options?.includeSegments && payload.length > appDataEnd && appDataEnd >= offset) {
        segments.push({
          name: 'Excess App Data',
          description: `Bytes beyond the ${MAX_ADVERT_DATA_SIZE}-byte app data limit (ignored by firmware)`,
          startByte: segmentOffset + appDataEnd,
          endByte: segmentOffset + payload.length - 1,
          value: bytesToHex(payload.subarray(appDataEnd))
        });
      }

      if (options?.includeSegments) {
        advert.segments = segments;
      }

      return advert;
    } catch (error) {
      return {
        type: PayloadType.Advert,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode advertisement payload'],
        publicKey: '',
        timestamp: 0,
        signature: '',
        appData: {
          flags: 0,
          deviceRole: DeviceRole.Unknown,
          hasLocation: false,
          hasName: false,
          hasFeature1: false,
          hasFeature2: false
        }
      };
    }
  }

  /**
   * Decode advertisement payload with signature verification
   */
  static async decodeWithVerification(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): Promise<AdvertPayload & { segments?: PayloadSegment[] } | null> {
    // First decode normally
    const advert = this.decode(payload, options);
    if (!advert || !advert.isValid) {
      return advert;
    }

    // Perform signature verification
    try {
      // Extract app_data from the payload (everything after public_key + timestamp + signature)
      // firmware only signs the first MAX_ADVERT_DATA_SIZE (32) bytes of app_data
      const appDataBytes = payload.subarray(APP_DATA_START, APP_DATA_START + MAX_ADVERT_DATA_SIZE);
      const appDataHex = bytesToHex(appDataBytes);

      const signatureValid = await Ed25519SignatureVerifier.verifyAdvertisementSignature(
        advert.publicKey,
        advert.signature,
        advert.timestamp,
        appDataHex
      );

      advert.signatureValid = signatureValid;
      
      if (!signatureValid) {
        advert.signatureError = 'Ed25519 signature verification failed';
        advert.isValid = false;
        if (!advert.errors) {
          advert.errors = [];
        }
        advert.errors.push('Invalid Ed25519 signature');
      }
    } catch (error) {
      advert.signatureValid = false;
      advert.signatureError = error instanceof Error ? error.message : 'Signature verification error';
      advert.isValid = false;
      if (!advert.errors) {
        advert.errors = [];
      }
      advert.errors.push('Signature verification failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }

    return advert;
  }

  // ADV_TYPE_* is the lower 4 bits; 0 is ADV_TYPE_NONE and 5..15 are reserved
  // for future types, so the raw value is preserved rather than guessed.
  private static parseDeviceRole(flags: number): DeviceRole {
    return (flags & 0x0F) as DeviceRole;
  }

  private static readUint32LE(buffer: Uint8Array, offset: number): number {
    return (buffer[offset] |
      (buffer[offset + 1] << 8) |
      (buffer[offset + 2] << 16) |
      (buffer[offset + 3] << 24)) >>> 0;
  }

  private static readInt32LE(buffer: Uint8Array, offset: number): number {
    const value = this.readUint32LE(buffer, offset);
    // convert unsigned to signed
    return value > 0x7FFFFFFF ? value - 0x100000000 : value;
  }

  private static sanitizeControlCharacters(value: string | null | undefined): string | null {
    if (!value) return null;
    const sanitized = value.trim().replace(/[\x00-\x1F\x7F]/g, '');
    return sanitized || null;
  }
}
