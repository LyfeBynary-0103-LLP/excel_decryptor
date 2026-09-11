# excel_decryptor

[![pub package](https://img.shields.io/pub/v/excel_decryptor.svg)](https://pub.dev/packages/excel_decryptor)
[![Dart CI](https://github.com/LyfeBynary-0103-LLP/excel_decryptor/actions/workflows/test.yml/badge.svg)](https://github.com/LyfeBynary-0103-LLP/excel_decryptor/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Dart Platforms](https://img.shields.io/badge/Platform-Pure%20Dart%20%7C%20Flutter-blue)](https://pub.dev/packages/excel_decryptor)

A lightweight, **100% pure-Dart** package to detect and decrypt password-protected Microsoft Excel (`.xlsx`) and Office Open XML (OOXML) files in memory.

Designed for Flutter mobile/web/desktop apps and server-side Dart backends that process password-protected files (such as e-statements from SBI, HDFC, ICICI, payroll, and financial reports).

---

## Highlights

- **100% Pure Dart**: Zero native C++/MethodChannel dependencies. Compiles seamlessly to iOS, Android, Web, Windows, macOS, Linux, and backend runtimes (Shelf, Dart Frog).
- **Modern Encryption Support**: Decrypts both **Agile Encryption** (AES-128/AES-256 with SHA-1, SHA-256, SHA-384, SHA-512) and **Standard Encryption** (AES-128-ECB).
- **Dynamic CFB Support**: Full Compound File Binary (OLE2) parser supporting both standard 512-byte sectors (CFB v3) and 4096-byte sectors (CFB v4).
- **Fast Password Validation**: Verifies password hashes before decrypting the complete file. Rejects wrong passwords in ~20-50 ms.
- **Zero Lock-in**: Decrypts encrypted documents directly into unencrypted OOXML ZIP bytes that can be read by any standard parser (e.g. `archive`, `excel`, `spreadsheet_decoder`).
- **No Dependency Conflicts**: Does not lock older versions of `archive` or Flutter SDKs.

---

## Feature Matrix

| Encryption Specification | Cipher / Key Size | Hash Function | Used In / Source | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Agile Encryption** (`[MS-OFFCRYPTO] 2.3.4.10`) | AES-CBC (128-bit) | SHA-1 | Core banking (Finacle, SBI statements) | Supported |
| **Agile Encryption** (`[MS-OFFCRYPTO] 2.3.4.10`) | AES-CBC (256-bit) | SHA-512 / SHA-256 | Microsoft Office 2013, 2016, 2019, 365 | Supported |
| **Standard Encryption** (`[MS-OFFCRYPTO] 2.3.4.5`) | AES-ECB (128-bit) | SHA-1 | Microsoft Office 2007, 2010, Apache POI | Supported |
| **CFB v3 & v4 Container** (`[MS-CFB]`) | Dynamic 512B / 4KB sectors | N/A | Large files (>2GB) and standard files | Supported |

---

## Getting Started

### Installation

Add `excel_decryptor` to your `pubspec.yaml`:

```yaml
dependencies:
  excel_decryptor: ^1.0.0
```

Or via terminal:

```bash
dart pub add excel_decryptor
# or for Flutter:
flutter pub add excel_decryptor
```

---

## Usage

### 1. Quick Check if a File is Protected

Check whether raw file bytes represent an encrypted Excel/OOXML workbook:

```dart
import 'dart:io';
import 'dart:typed_data';
import 'package:excel_decryptor/excel_decryptor.dart';

void main() async {
  final Uint8List fileBytes = await File('statement.xlsx').readAsBytes();

  if (ExcelDecryptor.isProtected(fileBytes)) {
    print('Password required!');
  } else {
    print('File is unencrypted, can be opened directly.');
  }
}
```

### 2. Simple Decryption

If the file is encrypted, decrypt it with the user's password. If the file is already unencrypted, `ExcelDecryptor.decrypt` returns the original bytes untouched.

```dart
import 'dart:io';
import 'dart:typed_data';
import 'package:excel_decryptor/excel_decryptor.dart';

void main() async {
  final Uint8List encryptedBytes = await File('statement.xlsx').readAsBytes();

  final Uint8List? decryptedBytes = ExcelDecryptor.decrypt(
    encryptedBytes,
    password: 'Password123',
  );

  if (decryptedBytes != null) {
    // Save or parse directly with your favorite Excel reader:
    await File('unlocked.xlsx').writeAsBytes(decryptedBytes);
    print('Decrypted successfully!');
  } else {
    print('Failed to decrypt. Password might be incorrect or file corrupted.');
  }
}
```

### 3. Detailed Decryption Status

Use `ExcelDecryptor.decryptWithResult` to receive detailed feedback on why decryption failed:

```dart
import 'dart:typed_data';
import 'package:excel_decryptor/excel_decryptor.dart';

void handleExcel(Uint8List fileBytes, String password) {
  final DecryptResult result = ExcelDecryptor.decryptWithResult(
    fileBytes,
    password: password,
  );

  switch (result.status) {
    case DecryptStatus.success:
      final Uint8List cleanZipBytes = result.bytes!;
      print('Unlocked! Byte size: ${cleanZipBytes.length}');
      break;

    case DecryptStatus.notProtected:
      print('File was not password protected.');
      break;

    case DecryptStatus.invalidPassword:
      print('Incorrect password: ${result.errorMessage}');
      break;

    case DecryptStatus.corruptedData:
      print('Corrupted or invalid spreadsheet: ${result.errorMessage}');
      break;

    case DecryptStatus.unsupportedFormat:
      print('Format not supported: ${result.errorMessage}');
      break;
  }
}
```

### 4. Integration with Excel Parsers

Once decrypted, the resulting bytes are standard unencrypted OOXML ZIP bytes, ready to be fed into any parser:

```dart
import 'package:archive/archive.dart';
import 'package:excel_decryptor/excel_decryptor.dart';

void parseDecryptedExcel(Uint8List encryptedBytes, String password) {
  final decryptedBytes = ExcelDecryptor.decrypt(encryptedBytes, password: password);
  if (decryptedBytes == null) throw Exception('Decryption failed');

  // Read with archive package:
  final archive = ZipDecoder().decodeBytes(decryptedBytes);
  for (final file in archive) {
    print('Found file inside package: ${file.name}');
  }
}
```

---

## Command-Line Example

You can run the bundled example directly from the repository:

```bash
dart run example/example.dart test/fixtures/sample_protected.xlsx Password123
```

---

## Security & Privacy

* **Zero Network Traffic**: All cryptographic operations occur entirely in-memory on the client machine. No documents or passwords ever leave the device.
* **Pure Dart Crypto**: Uses audited cryptographic primitives from Dart's official `crypto` and `pointycastle` libraries.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
