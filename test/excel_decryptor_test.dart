import 'dart:io';
import 'dart:typed_data';

import 'package:excel_decryptor/excel_decryptor.dart';
import 'package:excel_decryptor/src/cfb_parser.dart';
import 'package:test/test.dart';

void main() {
  group('ExcelDecryptor & CfbParser Tests', () {
    late Uint8List agileSha512Bytes;
    late Uint8List agileSha1Bytes;
    late Uint8List standardBytes;

    setUpAll(() async {
      final agileSha512File = File('test/fixtures/sample_protected.xlsx');
      expect(agileSha512File.existsSync(), isTrue,
          reason: 'Test fixture sample_protected.xlsx must exist');
      agileSha512Bytes = await agileSha512File.readAsBytes();

      final agileSha1File = File('test/fixtures/sample_agile_sha1.xlsx');
      expect(agileSha1File.existsSync(), isTrue,
          reason: 'Test fixture sample_agile_sha1.xlsx must exist');
      agileSha1Bytes = await agileSha1File.readAsBytes();

      final standardFile = File('test/fixtures/sample_standard_protected.xlsx');
      expect(standardFile.existsSync(), isTrue,
          reason: 'Test fixture sample_standard_protected.xlsx must exist');
      standardBytes = await standardFile.readAsBytes();
    });

    group('CfbParser Format Detection & Stream Extraction', () {
      test('correctly identifies CFB format and rejects non-CFB data', () {
        expect(CfbParser.isCfbFile(agileSha512Bytes), isTrue);
        expect(CfbParser.isCfbFile(agileSha1Bytes), isTrue);
        expect(CfbParser.isCfbFile(standardBytes), isTrue);

        // Standard unencrypted ZIP header (PK 0x50, 0x4B)
        final zipHeader = Uint8List.fromList(
            <int>[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);
        expect(CfbParser.isCfbFile(zipHeader), isFalse);

        // Short / empty bytes
        expect(CfbParser.isCfbFile(Uint8List(4)), isFalse);
        expect(CfbParser.isCfbFile(Uint8List(0)), isFalse);
      });

      test('extracts EncryptionInfo and EncryptedPackage streams from CFB', () {
        final streams = CfbParser.extractStreams(agileSha512Bytes);

        expect(streams.containsKey('EncryptionInfo'), isTrue);
        expect(streams.containsKey('EncryptedPackage'), isTrue);
        expect(streams['EncryptionInfo']!.isNotEmpty, isTrue);
        expect(streams['EncryptedPackage']!.isNotEmpty, isTrue);
      });
    });

    group('ExcelDecryptor.isProtected', () {
      test('identifies protected Excel files', () {
        expect(ExcelDecryptor.isProtected(agileSha512Bytes), isTrue);
        expect(ExcelDecryptor.isProtected(agileSha1Bytes), isTrue);
        expect(ExcelDecryptor.isProtected(standardBytes), isTrue);
      });

      test('identifies unencrypted files as not protected', () {
        final plainZipBytes = Uint8List.fromList(
            <int>[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
        expect(ExcelDecryptor.isProtected(plainZipBytes), isFalse);

        final csvBytes = Uint8List.fromList(
            'Date,Narration,Amount\n2024-01-01,Test,100'.codeUnits);
        expect(ExcelDecryptor.isProtected(csvBytes), isFalse);

        expect(ExcelDecryptor.isProtected(Uint8List(0)), isFalse);
        expect(ExcelDecryptor.isProtected(Uint8List(4)), isFalse);
      });
    });

    group('Agile Encryption Decryption (AES-256 + SHA-512, Office 365)', () {
      test('decrypts successfully with valid password', () {
        final decrypted = ExcelDecryptor.decrypt(
          agileSha512Bytes,
          password: 'Password123',
        );

        expect(decrypted, isNotNull);
        expect(decrypted!.length, greaterThan(0));

        // Unencrypted OOXML ZIP header starts with PK 0x50, 0x4B, 0x03, 0x04
        expect(decrypted[0], equals(0x50));
        expect(decrypted[1], equals(0x4B));
        expect(decrypted[2], equals(0x03));
        expect(decrypted[3], equals(0x04));
      });

      test(
          'decryptWithResult returns DecryptStatus.success with decrypted bytes',
          () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha512Bytes,
          password: 'Password123',
        );

        expect(result.status, equals(DecryptStatus.success));
        expect(result.isSuccess, isTrue);
        expect(result.bytes, isNotNull);
        expect(result.bytes![0], equals(0x50));
        expect(result.bytes![1], equals(0x4B));
      });

      test('rejects incorrect password with DecryptStatus.invalidPassword', () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha512Bytes,
          password: 'WrongPassword',
        );

        expect(result.status, equals(DecryptStatus.invalidPassword));
        expect(result.isSuccess, isFalse);
        expect(result.bytes, isNull);
        expect(result.errorMessage, isNotNull);

        final nullResult = ExcelDecryptor.decrypt(
          agileSha512Bytes,
          password: 'WrongPassword',
        );
        expect(nullResult, isNull);
      });

      test('rejects empty password with DecryptStatus.invalidPassword', () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha512Bytes,
          password: '',
        );

        expect(result.status, equals(DecryptStatus.invalidPassword));
        expect(result.bytes, isNull);
      });
    });

    group('Agile Encryption Decryption (AES-128 + SHA-1, SBI / Finacle format)',
        () {
      test('decrypts successfully with valid password', () {
        final decrypted = ExcelDecryptor.decrypt(
          agileSha1Bytes,
          password: 'Password123',
        );

        expect(decrypted, isNotNull);
        expect(decrypted!.length, greaterThan(0));
        expect(decrypted[0], equals(0x50));
        expect(decrypted[1], equals(0x4B));
      });

      test('rejects incorrect password', () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha1Bytes,
          password: 'WrongPassword',
        );

        expect(result.status, equals(DecryptStatus.invalidPassword));
        expect(result.bytes, isNull);
      });
    });

    group('Standard Encryption Decryption (AES-128 + SHA-1, Office 2007/2010)',
        () {
      test('decrypts successfully with valid password', () {
        final decrypted = ExcelDecryptor.decrypt(
          standardBytes,
          password: 'Password123',
        );

        expect(decrypted, isNotNull);
        expect(decrypted!.length, greaterThan(0));
        expect(decrypted[0], equals(0x50));
        expect(decrypted[1], equals(0x4B));
      });

      test('rejects incorrect password', () {
        final result = ExcelDecryptor.decryptWithResult(
          standardBytes,
          password: 'WrongPassword',
        );

        expect(result.status, equals(DecryptStatus.invalidPassword));
        expect(result.bytes, isNull);
      });
    });

    group('Unprotected and Malformed Files', () {
      test(
          'returns original bytes and DecryptStatus.notProtected for unencrypted ZIP',
          () {
        final plainZipBytes = Uint8List.fromList(
            <int>[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);
        final result =
            ExcelDecryptor.decryptWithResult(plainZipBytes, password: 'any');

        expect(result.status, equals(DecryptStatus.notProtected));
        expect(result.bytes, equals(plainZipBytes));

        final bytesResult =
            ExcelDecryptor.decrypt(plainZipBytes, password: 'any');
        expect(bytesResult, equals(plainZipBytes));
      });

      test('returns DecryptStatus.corruptedData for empty or truncated bytes',
          () {
        final result =
            ExcelDecryptor.decryptWithResult(Uint8List(2), password: 'any');
        expect(result.status, equals(DecryptStatus.corruptedData));
        expect(result.bytes, isNull);
      });

      test('handles corrupted CFB header cleanly', () {
        // Starts with CFB magic but truncated immediately
        final corruptCfb = Uint8List.fromList(<int>[
          0xD0,
          0xCF,
          0x11,
          0xE0,
          0xA1,
          0xB1,
          0x1A,
          0xE1,
          0x00,
          0x00,
          0x00,
          0x00,
        ]);
        final result =
            ExcelDecryptor.decryptWithResult(corruptCfb, password: 'any');
        expect(result.status, equals(DecryptStatus.corruptedData));
        expect(result.bytes, isNull);
      });
    });
  });
}
