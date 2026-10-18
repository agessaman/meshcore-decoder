// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { MeshCorePacketDecoder, PayloadType, AckPayload, PathPayload, PathPayloadDecoder, hexToBytes } from '../src';

const ACK_PACKET = '0D04B891647EBB40BA70';
const PATH_PACKET = '2105F464C77E411279399EFE1942B8A3FFA10F54D9C602FF2C8CF4';
const MULTIBYTE_ACK_PACKET = '0E41AABB11223344';
const MULTIBYTE_PATH_PACKET = '210042AABBCCDDEEFF00';

describe('Ack/Path Packet Decoding', () => {
  describe('Ack Packet', () => {
    it('should decode Ack packet structure correctly', () => {
      const result = MeshCorePacketDecoder.decode(ACK_PACKET);
      
      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Ack);
      expect(result.pathLength).toBe(4);
      
      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Ack) {
        const ackPayload = result.payload.decoded as AckPayload;
        
        expect(ackPayload.isValid).toBe(true);
        
        // Validate Ack payload structure with hex breakdown
        expect(ackPayload.checksum).toBe('BB40BA70'); // Bytes 0-3: CRC checksum as hex
      } else {
        fail('Ack payload not decoded correctly');
      }
    });

    it('should decode packet-level multi-byte paths correctly', () => {
      const result = MeshCorePacketDecoder.decode(MULTIBYTE_ACK_PACKET);

      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Ack);
      expect(result.pathLength).toBe(1);
      expect(result.pathHashSize).toBe(2);
      expect(result.path).toEqual(['AABB']);

      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Ack) {
        const ackPayload = result.payload.decoded as AckPayload;
        expect(ackPayload.isValid).toBe(true);
        expect(ackPayload.checksum).toBe('11223344');
      } else {
        fail('Ack payload not decoded correctly');
      }
    });
  });

  describe('Path Packet', () => {
    it('should decode the encrypted Path envelope (dest/src hashes, MAC, ciphertext)', () => {
      const result = MeshCorePacketDecoder.decode(PATH_PACKET);

      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Path);
      expect(result.pathLength).toBe(5); // 5 bytes in packet-level path
      expect(result.path).toEqual(['F4', '64', 'C7', '7E', '41']); // Packet-level path data
      expect(result.messageHash).toBe('A574CE1D');
      expect(result.totalBytes).toBe(27);

      const pathPayload = result.payload.decoded as PathPayload;
      expect(pathPayload.type).toBe(PayloadType.Path);
      expect(pathPayload.isValid).toBe(true);
      expect(pathPayload.destinationHash).toBe('12');
      expect(pathPayload.sourceHash).toBe('79');
      expect(pathPayload.cipherMac).toBe('399E');
      // returned path is encrypted: exactly one AES block
      expect(pathPayload.ciphertext).toBe('FE1942B8A3FFA10F54D9C602FF2C8CF4');
      expect(pathPayload.ciphertextLength).toBe(16);
      expect(pathPayload.decrypted).toBeUndefined();
    });

    it('should produce payload segments for Path packets', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(PATH_PACKET);
      expect(structure.payload.segments.map(s => s.name)).toEqual([
        'Destination Hash', 'Source Hash', 'Cipher MAC', 'Ciphertext'
      ]);
    });

    it('should reject Path payloads without ciphertext', () => {
      const result = MeshCorePacketDecoder.decode(MULTIBYTE_PATH_PACKET.slice(0, 12)); // 4-byte payload
      const pathPayload = result.payload.decoded as PathPayload;
      expect(pathPayload.isValid).toBe(false);
    });

    it('should parse decrypted Path plaintext with multi-byte hashes', () => {
      // path_len 0x42 = 2 hops x 2-byte hashes, extra type 0xEE (lower nibble 0x0E), extra FF00
      const plain = PathPayloadDecoder.parsePlaintext(hexToBytes('42AABBCCDDEEFF00'));
      expect(plain).toEqual({
        pathLength: 2,
        pathHashSize: 2,
        pathHashes: ['AABB', 'CCDD'],
        extraType: 0x0E,
        extraData: 'FF00'
      });
    });

    it('should reject invalid Path plaintext encodings', () => {
      expect(PathPayloadDecoder.parsePlaintext(hexToBytes('C1AA03'))).toBeNull(); // reserved hash size
      expect(PathPayloadDecoder.parsePlaintext(hexToBytes('BF' + '00'.repeat(200)))).toBeNull(); // 63 x 3 > 64 bytes
      expect(PathPayloadDecoder.parsePlaintext(hexToBytes('03AABB'))).toBeNull(); // truncated
    });
  });
});
