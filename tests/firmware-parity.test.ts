// Tests that mirror MeshCore firmware behaviour (src/Packet.cpp, src/Mesh.cpp,
// src/Dispatcher.cpp, src/Utils.cpp, src/helpers/*).

import { createCipheriv, createHash, createHmac } from 'crypto';
import {
  MeshCorePacketDecoder,
  PayloadType,
  DeviceRole,
  GroupDataPayload,
  GroupTextPayload,
  MultipartPayload,
  AdvertPayload,
  ChannelCrypto,
  Utils,
  bytesToHex
} from '../src';

const CHANNEL_KEY_128 = '8b3387e9c5cdea6ac9e5edbaa115cd72';
const CHANNEL_KEY_256 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

// firmware Utils::encryptThenMAC() with a channel/peer secret
function encryptThenMac(secretHex: string, plaintext: Buffer): Buffer {
  const secret = Buffer.alloc(32);
  Buffer.from(secretHex, 'hex').copy(secret);
  const padded = Buffer.alloc(Math.ceil(plaintext.length / 16) * 16);
  plaintext.copy(padded);
  const cipher = createCipheriv('aes-128-ecb', secret.subarray(0, 16), null);
  cipher.setAutoPadding(false);
  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);
  const mac = createHmac('sha256', secret).update(ciphertext).digest().subarray(0, 2);
  return Buffer.concat([mac, ciphertext]);
}

function channelHash(secretHex: string): Buffer {
  return createHash('sha256').update(Buffer.from(secretHex, 'hex')).digest().subarray(0, 1);
}

function flood(payloadType: PayloadType, payload: Buffer): string {
  return bytesToHex(Buffer.concat([Buffer.from([(payloadType << 2) | 0x01, 0x00]), payload]));
}

describe('Firmware parity', () => {
  describe('packet hash (Packet::calculatePacketHash)', () => {
    it('hashes payload type + payload, ignoring header route bits and path', () => {
      const payload = Buffer.from('04B891647E', 'hex');
      const expected = createHash('sha256')
        .update(Buffer.concat([Buffer.from([PayloadType.Ack]), payload]))
        .digest('hex').slice(0, 16).toUpperCase();

      const floodPkt = MeshCorePacketDecoder.decode('0D00' + payload.toString('hex'));
      const directPkt = MeshCorePacketDecoder.decode('0E02AABB' + payload.toString('hex'));
      expect(floodPkt.packetHash).toBe(expected);
      expect(directPkt.packetHash).toBe(expected);
    });

    it('includes path_len as a little-endian uint16 for TRACE packets', () => {
      const payload = Buffer.from('0102030405060708' + '00' + 'AABB', 'hex');
      const hex = (pathLen: number) =>
        '26' + pathLen.toString(16).padStart(2, '0') + '00'.repeat(pathLen) + payload.toString('hex');
      const expected = (pathLen: number) => createHash('sha256')
        .update(Buffer.concat([Buffer.from([PayloadType.Trace, pathLen, 0]), payload]))
        .digest('hex').slice(0, 16).toUpperCase();

      expect(MeshCorePacketDecoder.decode(hex(0)).packetHash).toBe(expected(0));
      expect(MeshCorePacketDecoder.decode(hex(2)).packetHash).toBe(expected(2));
      expect(MeshCorePacketDecoder.decode(hex(0)).packetHash).not.toBe(MeshCorePacketDecoder.decode(hex(2)).packetHash);
    });
  });

  describe('Dispatcher::tryParsePacket rejection rules', () => {
    it('marks packets with payload version > 1 as invalid but still decodes them', () => {
      const result = MeshCorePacketDecoder.decode('4D00B891647E');
      expect(result.isValid).toBe(false);
      expect(result.payloadVersion).toBe(1);
      expect(result.payloadType).toBe(PayloadType.Ack);
      expect(result.errors?.[0]).toMatch(/version/);
      expect(MeshCorePacketDecoder.validate('4D00B891647E').isValid).toBe(false);
    });

    it('marks paths longer than 64 bytes as invalid', () => {
      // 0x96 = 22 hops x 3-byte hashes = 66 bytes
      const hex = '0D96' + 'AA'.repeat(66) + 'B891647E';
      const result = MeshCorePacketDecoder.decode(hex);
      expect(result.isValid).toBe(false);
      expect(result.errors?.[0]).toMatch(/Path too long/);
      expect(MeshCorePacketDecoder.validate(hex).isValid).toBe(false);
    });

    it('marks payloads longer than 184 bytes as invalid', () => {
      const hex = '3D00' + '00'.repeat(185);
      const result = MeshCorePacketDecoder.decode(hex);
      expect(result.isValid).toBe(false);
      expect(result.errors?.[0]).toMatch(/Payload too long/);
      expect(MeshCorePacketDecoder.validate(hex).isValid).toBe(false);
      expect(MeshCorePacketDecoder.validate('3D00' + '00'.repeat(184)).isValid).toBe(true);
    });
  });

  describe('transport codes', () => {
    it('labels transport code 1 as reserved', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure('0C341200000000B891647E');
      const names = structure.segments.map(s => s.name);
      expect(names).toContain('Region/Scope (transport code 0)');
      expect(names).toContain('Reserved (transport code 1)');
    });
  });

  describe('GRP_DATA', () => {
    it('decodes the envelope and decrypts data_type/data_len/data', () => {
      const plain = Buffer.from([0x40, 0x01, 0x03, 0xDE, 0xAD, 0xBE]); // type 0x0140, len 3
      const payload = Buffer.concat([channelHash(CHANNEL_KEY_128), encryptThenMac(CHANNEL_KEY_128, plain)]);
      const keyStore = MeshCorePacketDecoder.createKeyStore({ channelSecrets: [CHANNEL_KEY_128] });

      const result = MeshCorePacketDecoder.decode(flood(PayloadType.GroupData, payload), { keyStore });
      const groupData = result.payload.decoded as GroupDataPayload;
      expect(result.isValid).toBe(true);
      expect(groupData.type).toBe(PayloadType.GroupData);
      expect(groupData.channelHash).toBe(bytesToHex(channelHash(CHANNEL_KEY_128)));
      expect(groupData.ciphertextLength).toBe(16);
      expect(groupData.decrypted).toEqual({ dataType: 0x0140, dataLength: 3, data: 'DEADBE' });

      const withoutKey = MeshCorePacketDecoder.decode(flood(PayloadType.GroupData, payload));
      expect((withoutKey.payload.decoded as GroupDataPayload).decrypted).toBeUndefined();
    });

    it('rejects decrypted data whose data_len exceeds the available bytes', () => {
      const plain = Buffer.alloc(16);
      plain[2] = 14; // only 13 bytes follow the 3-byte header
      const result = ChannelCrypto.decryptGroupData(
        encryptThenMac(CHANNEL_KEY_128, plain).subarray(2).toString('hex'),
        encryptThenMac(CHANNEL_KEY_128, plain).subarray(0, 2).toString('hex'),
        CHANNEL_KEY_128
      );
      expect(result.success).toBe(false);
    });
  });

  describe('channel crypto', () => {
    it('decrypts GRP_TXT with a 256-bit channel secret (AES-128 on the first 16 bytes)', () => {
      const plain = Buffer.concat([Buffer.from([0x10, 0x00, 0x00, 0x00, 0x01]), Buffer.from('alice: hi')]);
      const payload = Buffer.concat([channelHash(CHANNEL_KEY_256), encryptThenMac(CHANNEL_KEY_256, plain)]);
      const keyStore = MeshCorePacketDecoder.createKeyStore({ channelSecrets: [CHANNEL_KEY_256] });

      const result = MeshCorePacketDecoder.decode(flood(PayloadType.GroupText, payload), { keyStore });
      const groupText = result.payload.decoded as GroupTextPayload;
      expect(groupText.decrypted).toMatchObject({
        timestamp: 0x10,
        flags: 0x01,
        txtType: 0,
        attempt: 1,
        sender: 'alice',
        message: 'hi'
      });
    });

    it('rejects ciphertext that is not block-aligned', () => {
      const result = ChannelCrypto.decryptChannelPayload('00'.repeat(15), '0000', CHANNEL_KEY_128);
      expect(result.success).toBe(false);
    });
  });

  describe('MULTIPART', () => {
    it('decodes a multipart ACK (Mesh::createMultiAck)', () => {
      const result = MeshCorePacketDecoder.decode(flood(PayloadType.Multipart, Buffer.from('23B891647E', 'hex')));
      const multipart = result.payload.decoded as MultipartPayload;
      expect(multipart.isValid).toBe(true);
      expect(multipart.remaining).toBe(2);
      expect(multipart.innerType).toBe(PayloadType.Ack);
      expect(multipart.ackChecksum).toBe('B891647E');
    });

    it('rejects too-short multipart payloads', () => {
      const result = MeshCorePacketDecoder.decode(flood(PayloadType.Multipart, Buffer.from('23B8', 'hex')));
      expect((result.payload.decoded as MultipartPayload).isValid).toBe(false);
    });
  });

  describe('ADVERT app data', () => {
    const keyPair = {
      publicKey: '4852b69364572b52efa1b6bb3e6d0abed4f389a1cbfbb60a9bba2cce649caf0e',
      privateKey: '18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5'
    };

    async function buildAdvert(appData: Buffer, signedAppData: Buffer = appData): Promise<string> {
      const timestamp = Buffer.from([0x00, 0x10, 0x20, 0x30]);
      const pub = Buffer.from(keyPair.publicKey, 'hex');
      const message = Buffer.concat([pub, timestamp, signedAppData]).toString('hex');
      const signature = Buffer.from(await Utils.sign(message, keyPair.privateKey, keyPair.publicKey), 'hex');
      return flood(PayloadType.Advert, Buffer.concat([pub, timestamp, signature, appData]));
    }

    it('exposes feature fields and preserves unknown device roles', async () => {
      // flags: type 0 (NONE) | feat1 | feat2 | name
      const appData = Buffer.concat([Buffer.from([0xE0, 0x34, 0x12, 0x78, 0x56]), Buffer.from('node')]);
      const result = await MeshCorePacketDecoder.decodeWithVerification(await buildAdvert(appData));
      const advert = result.payload.decoded as AdvertPayload;
      expect(result.isValid).toBe(true);
      expect(advert.signatureValid).toBe(true);
      expect(advert.appData.deviceRole).toBe(DeviceRole.Unknown);
      expect(advert.appData.hasFeature1).toBe(true);
      expect(advert.appData.feature1).toBe(0x1234);
      expect(advert.appData.feature2).toBe(0x5678);
      expect(advert.appData.name).toBe('node');
    });

    it('only signs and parses the first 32 bytes of app data', async () => {
      const appData = Buffer.concat([Buffer.from([0x81]), Buffer.from('A'.repeat(40))]);
      const hex = await buildAdvert(appData, appData.subarray(0, 32));
      const result = await MeshCorePacketDecoder.decodeWithVerification(hex);
      const advert = result.payload.decoded as AdvertPayload;
      expect(advert.signatureValid).toBe(true);
      expect(advert.appData.name).toBe('A'.repeat(31));
    });

    it('flags truncated location data as invalid', () => {
      const pub = Buffer.alloc(32, 1);
      const payload = Buffer.concat([pub, Buffer.alloc(4), Buffer.alloc(64), Buffer.from([0x92, 0x01, 0x02])]);
      const advert = MeshCorePacketDecoder.decode(flood(PayloadType.Advert, payload)).payload.decoded as AdvertPayload;
      expect(advert.isValid).toBe(false);
      expect(advert.appData.deviceRole).toBe(DeviceRole.Repeater);
      expect(advert.appData.location).toBeUndefined();
    });
  });
});
