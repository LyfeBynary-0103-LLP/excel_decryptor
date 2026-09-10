import 'dart:io';
import 'dart:typed_data';

import 'package:excel_decryptor/excel_decryptor.dart';

void main(List<String> args) async {
  if (args.length < 2) {
    print(
        'Usage: dart run example/example.dart <path-to-excel-file> <password>');
    print('');
    print('Example:');
    print(
        '  dart run example/example.dart test/fixtures/sample_protected.xlsx Password123');
    return;
  }

  final filePath = args[0];
  final password = args[1];

  final file = File(filePath);
  if (!file.existsSync()) {
    print('Error: File not found: $filePath');
    exit(1);
  }

  final Uint8List fileBytes = await file.readAsBytes();
  print('Read ${fileBytes.length} bytes from: $filePath');

  // 1. Fast check if the file is password-protected
  final isEncrypted = ExcelDecryptor.isProtected(fileBytes);
  print('Is password protected: $isEncrypted');

  if (!isEncrypted) {
    print('The file is not password protected. You can parse it directly.');
    return;
  }

  // 2. Decrypt with detailed status feedback
  final stopwatch = Stopwatch()..start();
  final DecryptResult result = ExcelDecryptor.decryptWithResult(
    fileBytes,
    password: password,
  );
  stopwatch.stop();

  if (result.isSuccess) {
    final Uint8List decryptedBytes = result.bytes!;
    print(' Successfully decrypted in ${stopwatch.elapsedMilliseconds} ms!');
    print('Decrypted size: ${decryptedBytes.length} bytes');
    print(
        'ZIP Magic Header: 0x${decryptedBytes[0].toRadixString(16).toUpperCase()} 0x${decryptedBytes[1].toRadixString(16).toUpperCase()}');

    // You can now pass `decryptedBytes` to packages like `excel`, `spreadsheet_decoder`, or `archive`!
  } else {
    print(' Decryption failed!');
    print('Status: ${result.status}');
    print('Reason: ${result.errorMessage}');
  }
}
