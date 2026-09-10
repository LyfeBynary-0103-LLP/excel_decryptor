import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:excel_decryptor/excel_decryptor.dart';
import 'package:excel_decryptor/src/cfb_parser.dart';
import 'package:test/test.dart';

void main() {
  group('ExcelDecryptor End-to-End Suite', () {
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

    group('Format Detection & CFB Container Parsing', () {
      test('correctly identifies CFB format on all 3 fixtures', () {
        expect(CfbParser.isCfbFile(agileSha512Bytes), isTrue);
        expect(CfbParser.isCfbFile(agileSha1Bytes), isTrue);
        expect(CfbParser.isCfbFile(standardBytes), isTrue);
      });

      test('rejects non-CFB magic bytes', () {
        // Standard unencrypted ZIP header (PK 0x50, 0x4B)
        final zipHeader = Uint8List.fromList(
            <int>[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);
        expect(CfbParser.isCfbFile(zipHeader), isFalse);

        // PDF signature (%PDF)
        final pdfHeader = Uint8List.fromList(
            <int>[0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34]);
        expect(CfbParser.isCfbFile(pdfHeader), isFalse);

        // PNG signature (\x89PNG)
        final pngHeader = Uint8List.fromList(
            <int>[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        expect(CfbParser.isCfbFile(pngHeader), isFalse);

        // Short / empty bytes
        expect(CfbParser.isCfbFile(Uint8List(7)), isFalse);
        expect(CfbParser.isCfbFile(Uint8List(0)), isFalse);
      });

      test(
          'extracts EncryptionInfo and EncryptedPackage streams from all 3 fixtures',
          () {
        for (final fixture in [
          agileSha512Bytes,
          agileSha1Bytes,
          standardBytes
        ]) {
          final streams = CfbParser.extractStreams(fixture);
          expect(streams.containsKey('EncryptionInfo'), isTrue);
          expect(streams.containsKey('EncryptedPackage'), isTrue);
          expect(streams['EncryptionInfo']!.isNotEmpty, isTrue);
          expect(streams['EncryptedPackage']!.isNotEmpty, isTrue);
        }
      });
    });

    group('ExcelDecryptor.isProtected', () {
      test('identifies protected files across Agile and Standard formats', () {
        expect(ExcelDecryptor.isProtected(agileSha512Bytes), isTrue);
        expect(ExcelDecryptor.isProtected(agileSha1Bytes), isTrue);
        expect(ExcelDecryptor.isProtected(standardBytes), isTrue);
      });

      test('identifies unencrypted files and non-Excel data as not protected',
          () {
        // Plain ZIP
        final plainZipBytes = Uint8List.fromList(
            <int>[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
        expect(ExcelDecryptor.isProtected(plainZipBytes), isFalse);

        // CSV text
        final csvBytes = Uint8List.fromList(
            'Date,Narration,Amount\n2024-01-01,Salary,50000'.codeUnits);
        expect(ExcelDecryptor.isProtected(csvBytes), isFalse);

        // Plain text JSON
        final jsonBytes = Uint8List.fromList('{"status": "ok"}'.codeUnits);
        expect(ExcelDecryptor.isProtected(jsonBytes), isFalse);

        // Edge sizes
        expect(ExcelDecryptor.isProtected(Uint8List(0)), isFalse);
        expect(ExcelDecryptor.isProtected(Uint8List(7)), isFalse);
        expect(ExcelDecryptor.isProtected(Uint8List(512)), isFalse);
      });
    });

    group('Fixture 1: Modern Agile Encryption (AES-256 + SHA-512, Office 365)',
        () {
      const validPassword = 'Password123';

      test('decrypts into valid OOXML ZIP bytes', () {
        final decrypted = ExcelDecryptor.decrypt(
          agileSha512Bytes,
          password: validPassword,
        );

        expect(decrypted, isNotNull);
        expect(decrypted!.length, greaterThan(100));

        // Unencrypted OOXML ZIP header starts with PK (0x50, 0x4B, 0x03, 0x04)
        expect(decrypted[0], equals(0x50));
        expect(decrypted[1], equals(0x4B));
        expect(decrypted[2], equals(0x03));
        expect(decrypted[3], equals(0x04));
      });

      test('decrypted payload unpacks and contains valid workbook XML files',
          () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha512Bytes,
          password: validPassword,
        );

        expect(result.status, equals(DecryptStatus.success));
        expect(result.isSuccess, isTrue);

        // Verify the unencrypted ZIP package
        final archive = ZipDecoder().decodeBytes(result.bytes!);
        final fileNames = archive.files.map((f) => f.name).toSet();

        expect(fileNames, contains('[Content_Types].xml'));
        expect(fileNames, contains('xl/workbook.xml'));
        expect(fileNames, contains('_rels/.rels'));

        // Verify workbook XML content
        final workbookFile = archive.findFile('xl/workbook.xml');
        expect(workbookFile, isNotNull);
        final workbookXml = utf8.decode(workbookFile!.content as List<int>);
        expect(workbookXml, contains('workbook'));
      });

      test('is case-sensitive and rejects incorrect password variations', () {
        final variations = [
          'password123',
          'PASSWORD123',
          'Password124',
          'WrongPassword',
          'admin'
        ];
        for (final pwd in variations) {
          final result = ExcelDecryptor.decryptWithResult(
            agileSha512Bytes,
            password: pwd,
          );
          expect(result.status, equals(DecryptStatus.invalidPassword),
              reason: 'Password "$pwd" should be rejected');
          expect(result.bytes, isNull);
        }
      });

      test('rejects passwords with extra spaces', () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha512Bytes,
          password: ' Password123 ',
        );
        expect(result.status, equals(DecryptStatus.invalidPassword));
      });

      test('handles empty password cleanly', () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha512Bytes,
          password: '',
        );
        expect(result.status, equals(DecryptStatus.invalidPassword));
        expect(result.errorMessage, contains('empty'));
      });

      test('handles long password strings without crashing', () {
        final longPassword = 'A' * 2048;
        final result = ExcelDecryptor.decryptWithResult(
          agileSha512Bytes,
          password: longPassword,
        );
        expect(result.status, equals(DecryptStatus.invalidPassword));
      });

      test('handles unicode / emojis in password gracefully', () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha512Bytes,
          password: 'Password🔐123',
        );
        expect(result.status, equals(DecryptStatus.invalidPassword));
      });
    });

    group(
        'Fixture 2: Agile Encryption (AES-128 + SHA-1, SBI / Finacle Banking format)',
        () {
      const validPassword = 'Password123';

      test('decrypts into valid OOXML ZIP bytes', () {
        final decrypted = ExcelDecryptor.decrypt(
          agileSha1Bytes,
          password: validPassword,
        );

        expect(decrypted, isNotNull);
        final bytes = decrypted!;
        expect(bytes[0], equals(0x50));
        expect(bytes[1], equals(0x4B));
      });

      test('decrypted payload unpacks and contains valid workbook XML files',
          () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha1Bytes,
          password: validPassword,
        );

        expect(result.status, equals(DecryptStatus.success));

        final archive = ZipDecoder().decodeBytes(result.bytes!);
        final fileNames = archive.files.map((f) => f.name).toSet();

        expect(fileNames, contains('[Content_Types].xml'));
        expect(fileNames, contains('xl/workbook.xml'));

        final workbookFile = archive.findFile('xl/workbook.xml');
        expect(workbookFile, isNotNull);
        final workbookXml = utf8.decode(workbookFile!.content as List<int>);
        expect(workbookXml, contains('workbook'));
      });

      test('rejects incorrect password', () {
        final result = ExcelDecryptor.decryptWithResult(
          agileSha1Bytes,
          password: 'IncorrectPassword',
        );

        expect(result.status, equals(DecryptStatus.invalidPassword));
        expect(result.bytes, isNull);
      });
    });

    group('Fixture 3: Standard Encryption (AES-128 + SHA-1, Office 2007/2010)',
        () {
      const validPassword = 'Password123';

      test('decrypts into valid OOXML ZIP bytes', () {
        final decrypted = ExcelDecryptor.decrypt(
          standardBytes,
          password: validPassword,
        );

        expect(decrypted, isNotNull);
        final bytes = decrypted!;
        expect(bytes[0], equals(0x50));
        expect(bytes[1], equals(0x4B));
      });

      test('decrypted payload unpacks and contains valid workbook XML files',
          () {
        final result = ExcelDecryptor.decryptWithResult(
          standardBytes,
          password: validPassword,
        );

        expect(result.status, equals(DecryptStatus.success));

        final archive = ZipDecoder().decodeBytes(result.bytes!);
        final fileNames = archive.files.map((f) => f.name).toSet();

        expect(fileNames, contains('[Content_Types].xml'));
        expect(fileNames, contains('xl/workbook.xml'));

        final workbookFile = archive.findFile('xl/workbook.xml');
        expect(workbookFile, isNotNull);
        final workbookXml = utf8.decode(workbookFile!.content as List<int>);
        expect(workbookXml, contains('workbook'));
      });

      test('rejects incorrect password', () {
        final result = ExcelDecryptor.decryptWithResult(
          standardBytes,
          password: 'IncorrectPassword',
        );

        expect(result.status, equals(DecryptStatus.invalidPassword));
        expect(result.bytes, isNull);
      });
    });

    group('Unprotected Files & Fallback Handling', () {
      test(
          'returns original bytes and DecryptStatus.notProtected for unencrypted ZIP',
          () {
        final plainZipBytes = Uint8List.fromList(
            <int>[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);
        final result =
            ExcelDecryptor.decryptWithResult(plainZipBytes, password: 'any');

        expect(result.status, equals(DecryptStatus.notProtected));
        expect(result.bytes, equals(plainZipBytes));

        final directBytes =
            ExcelDecryptor.decrypt(plainZipBytes, password: 'any');
        expect(directBytes, equals(plainZipBytes));
      });

      test('returns original bytes for non-CFB plain text / CSV', () {
        final csvBytes =
            Uint8List.fromList('Account,Balance\n123456789,10000.50'.codeUnits);
        final result =
            ExcelDecryptor.decryptWithResult(csvBytes, password: 'any');

        expect(result.status, equals(DecryptStatus.notProtected));
        expect(result.bytes, equals(csvBytes));
      });

      test(
          'idempotence: multiple decrypt calls on same bytes return identical results',
          () {
        final res1 =
            ExcelDecryptor.decrypt(agileSha512Bytes, password: 'Password123');
        final res2 =
            ExcelDecryptor.decrypt(agileSha512Bytes, password: 'Password123');

        expect(res1, isNotNull);
        expect(res2, isNotNull);
        expect(res1, equals(res2));
      });
    });

    group('Malformed & Corrupted Data Handling', () {
      test('returns DecryptStatus.corruptedData for empty byte array', () {
        final result =
            ExcelDecryptor.decryptWithResult(Uint8List(0), password: 'any');
        expect(result.status, equals(DecryptStatus.corruptedData));
        expect(result.bytes, isNull);
      });

      test(
          'returns DecryptStatus.corruptedData for truncated byte array (< 8 bytes)',
          () {
        final result =
            ExcelDecryptor.decryptWithResult(Uint8List(5), password: 'any');
        expect(result.status, equals(DecryptStatus.corruptedData));
        expect(result.bytes, isNull);
      });

      test('handles truncated CFB magic bytes gracefully', () {
        final truncatedCfb = Uint8List.fromList(<int>[
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
          0x00,
          0x00,
        ]);
        final result =
            ExcelDecryptor.decryptWithResult(truncatedCfb, password: 'any');
        expect(result.status, equals(DecryptStatus.corruptedData));
        expect(result.bytes, isNull);
      });

      test('handles corrupted sector chain gracefully', () {
        final corruptedBytes = Uint8List.fromList(agileSha512Bytes);
        // Corrupt sector header bytes
        for (int i = 76; i < 150; i++) {
          corruptedBytes[i] = 0xFF;
        }

        final result = ExcelDecryptor.decryptWithResult(corruptedBytes,
            password: 'Password123');
        expect(result.isSuccess, isFalse);
        expect(result.bytes, isNull);
      });
    });
  });
}
