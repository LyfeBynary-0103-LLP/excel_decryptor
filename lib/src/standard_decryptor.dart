import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/ecb.dart';

/// Decryptor for Microsoft Office OpenXML (OOXML) Standard Encryption.
/// Used by Microsoft Office 2007/2010 and banking systems (Apache POI / Finacle) for password-protected Excel files.
/// Spec: [MS-OFFCRYPTO] 2.3.4.5 - 2.3.4.9 (ECMA-376 Standard Encryption).
class StandardDecryptor {
  /// Decrypts [encryptedPackageBytes] using [encryptionInfoBytes] and [password].
  /// Returns the decrypted raw `.xlsx` ZIP bytes, or `null` if password is incorrect or data is invalid.
  static Uint8List? decryptPackage({
    required Uint8List encryptionInfoBytes,
    required Uint8List encryptedPackageBytes,
    required String password,
  }) {
    try {
      if (encryptionInfoBytes.length < 52) {
        return null;
      }
      final bd = ByteData.sublistView(encryptionInfoBytes);

      // Offset 0: vMajor (2 bytes), vMinor (2 bytes)
      final vMinor = bd.getUint16(2, Endian.little);
      if (vMinor != 2) {
        return null;
      }

      // Offset 8: headerSize (4 bytes)
      final headerSize = bd.getUint32(8, Endian.little);

      // Offset 12: EncryptionHeader
      // Offset 12+16: KeySize (4 bytes, e.g. 128)
      final keySize = bd.getUint32(12 + 16, Endian.little);
      final keyBytesLen = keySize > 0 ? keySize ~/ 8 : 16;

      // EncryptionVerifier starts at offset 12 + headerSize
      int verifierOffset = 12 + headerSize;
      if (verifierOffset + 52 > encryptionInfoBytes.length) {
        // Fallback: standard verifier offset when headerSize is 140 (0x8C)
        verifierOffset = 12 + 140;
      }

      if (verifierOffset + 52 > encryptionInfoBytes.length) {
        return null;
      }

      final saltSize = bd.getUint32(verifierOffset, Endian.little);
      final salt = encryptionInfoBytes.sublist(
          verifierOffset + 4, verifierOffset + 4 + saltSize);
      final verifierPos = verifierOffset + 4 + saltSize;
      final encryptedVerifier =
          encryptionInfoBytes.sublist(verifierPos, verifierPos + 16);
      final verifierHashSizePos = verifierPos + 16;
      final verifierHashSize = bd.getUint32(verifierHashSizePos, Endian.little);
      final encryptedVerifierHashPos = verifierHashSizePos + 4;
      final encryptedVerifierHash = encryptionInfoBytes.sublist(
        encryptedVerifierHashPos,
        encryptedVerifierHashPos + 32,
      );

      // 1. Derive key from password
      final key = _convertPasswordToKey(
        password: password,
        salt: salt,
        keyLength: keyBytesLen,
      );

      // 2. Verify password against verifier hash
      final isValid = _verifyKey(
        key: key,
        encryptedVerifier: encryptedVerifier,
        encryptedVerifierHash: encryptedVerifierHash,
        verifierHashSize: verifierHashSize,
      );

      if (!isValid) {
        return null;
      }

      // 3. Decrypt package payload
      final decrypted =
          _decryptPackagePayload(key: key, input: encryptedPackageBytes);

      // Verify PK zip header
      if (decrypted.length > 2 &&
          decrypted[0] == 0x50 &&
          decrypted[1] == 0x4B) {
        return decrypted;
      }

      return null;
    } catch (_) {
      return null;
    }
  }

  static Uint8List _convertPasswordToKey({
    required String password,
    required Uint8List salt,
    required int keyLength,
  }) {
    const iterCount = 50000;
    // UTF-16LE encoding of password per MS-OFFCRYPTO §2.3.4.7
    final passwordBytes = <int>[];
    for (final unit in password.codeUnits) {
      passwordBytes.add(unit & 0xFF);
      passwordBytes.add((unit >> 8) & 0xFF);
    }

    var saltedHash = sha1.convert(<int>[...salt, ...passwordBytes]).bytes;

    for (int i = 0; i < iterCount; i++) {
      final iterBytes = <int>[
        i & 0xFF,
        (i >> 8) & 0xFF,
        (i >> 16) & 0xFF,
        (i >> 24) & 0xFF,
      ];
      saltedHash = sha1.convert(<int>[...iterBytes, ...saltedHash]).bytes;
    }

    final block0 = <int>[0, 0, 0, 0];
    final hfinal = sha1.convert(<int>[...saltedHash, ...block0]).bytes;
    const cbHash = 20;

    final buf1 = Uint8List(64);
    buf1.fillRange(0, 64, 0x36);
    for (int i = 0; i < cbHash; i++) {
      buf1[i] = hfinal[i] ^ 0x36;
    }
    final x1 = sha1.convert(buf1).bytes;

    final buf2 = Uint8List(64);
    buf2.fillRange(0, 64, 0x5C);
    for (int i = 0; i < cbHash; i++) {
      buf2[i] = hfinal[i] ^ 0x5C;
    }
    final x2 = sha1.convert(buf2).bytes;

    final x3 = <int>[...x1, ...x2];
    return Uint8List.fromList(x3.sublist(0, keyLength));
  }

  static bool _verifyKey({
    required Uint8List key,
    required Uint8List encryptedVerifier,
    required Uint8List encryptedVerifierHash,
    required int verifierHashSize,
  }) {
    try {
      final verifier = _aesEcbDecrypt(key, encryptedVerifier);
      final expectedHash = sha1.convert(verifier).bytes;
      final decryptedHash = _aesEcbDecrypt(key, encryptedVerifierHash);

      for (int i = 0;
          i < verifierHashSize &&
              i < expectedHash.length &&
              i < decryptedHash.length;
          i++) {
        if (expectedHash[i] != decryptedHash[i]) return false;
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  static Uint8List _decryptPackagePayload({
    required Uint8List key,
    required Uint8List input,
  }) {
    const offset = 8;
    const blockSize = 16;
    const chunkSize = 4096;

    final outputChunks = <Uint8List>[];
    int start = 0;
    int end = 0;
    final totalPayload = input.length - offset;

    while (end < totalPayload) {
      start = end;
      end = start + chunkSize;
      if (end > totalPayload) end = totalPayload;

      var chunk = input.sublist(start + offset, end + offset);
      final remainder = chunk.length % blockSize;
      if (remainder != 0) {
        final padded = Uint8List(chunk.length + (blockSize - remainder));
        padded.setRange(0, chunk.length, chunk);
        chunk = padded;
      }

      final decrypted = _aesEcbDecrypt(key, chunk);
      outputChunks.add(decrypted);
    }

    final totalLen =
        outputChunks.fold<int>(0, (int sum, Uint8List c) => sum + c.length);
    final combined = Uint8List(totalLen);
    int pos = 0;
    for (final c in outputChunks) {
      combined.setRange(pos, pos + c.length, c);
      pos += c.length;
    }

    final bd = ByteData.sublistView(input);
    final streamSize = bd.getUint32(0, Endian.little);
    if (streamSize > 0 && streamSize <= combined.length) {
      return combined.sublist(0, streamSize);
    }
    return combined;
  }

  static Uint8List _aesEcbDecrypt(Uint8List key, Uint8List input) {
    final cipher = ECBBlockCipher(AESEngine());
    cipher.init(false, KeyParameter(key));
    final output = Uint8List(input.length);
    for (int i = 0; i < input.length; i += 16) {
      cipher.processBlock(input, i, output, i);
    }
    return output;
  }
}
