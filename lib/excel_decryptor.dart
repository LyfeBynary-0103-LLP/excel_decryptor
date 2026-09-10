import 'dart:typed_data';

import 'src/agile_decryptor.dart';
import 'src/cfb_parser.dart';
import 'src/decrypt_result.dart';
import 'src/standard_decryptor.dart';

export 'src/decrypt_result.dart';

/// The primary entry point to detect and decrypt password-protected Microsoft Excel (.xlsx)
/// and Office Open XML (OOXML) documents.
class ExcelDecryptor {
  /// Checks whether the provided raw [bytes] represent a password-protected OOXML/Excel file.
  ///
  /// Returns `true` if the file is encapsulated within a Microsoft Compound File Binary (CFB)
  /// container containing `EncryptionInfo` and `EncryptedPackage` streams.
  ///
  /// Fast-paths unencrypted ZIP archives (starting with `PK`), CSV, and plain text files to return `false`.
  static bool isProtected(Uint8List bytes) {
    if (bytes.length < 8) return false;

    // Fast-path: standard unencrypted ZIP starts with 'PK' (0x50, 0x4B)
    if (bytes[0] == 0x50 && bytes[1] == 0x4B) {
      return false;
    }

    // Encrypted OOXML Excel files are stored inside Microsoft OLE CFB containers
    if (CfbParser.isCfbFile(bytes)) {
      try {
        final streams = CfbParser.extractStreams(bytes);
        return streams.containsKey('EncryptedPackage') &&
            streams.containsKey('EncryptionInfo');
      } catch (_) {
        return false;
      }
    }

    return false;
  }

  /// Attempts to decrypt password-protected Excel [bytes] using the provided [password].
  ///
  /// - If the file is **not protected**, returns the original [bytes].
  /// - If decryption **succeeds**, returns the decrypted `.xlsx` (unencrypted ZIP) bytes.
  /// - If the password is **incorrect** or data is **corrupt**, returns `null`.
  ///
  /// For more detailed status codes and error messages, use [decryptWithResult].
  static Uint8List? decrypt(Uint8List bytes, {required String password}) {
    final result = decryptWithResult(bytes, password: password);
    return result.isSuccess || result.status == DecryptStatus.notProtected
        ? result.bytes
        : null;
  }

  /// Decrypts password-protected Excel [bytes] using the provided [password],
  /// returning a structured [DecryptResult] with status information.
  ///
  /// Inspect [DecryptResult.status] to determine whether the operation succeeded,
  /// the password was incorrect, the file was not protected, or data was corrupt.
  static DecryptResult decryptWithResult(Uint8List bytes,
      {required String password}) {
    if (bytes.length < 8) {
      return const DecryptResult(
        status: DecryptStatus.corruptedData,
        errorMessage:
            'File data is empty or too short to be a valid spreadsheet.',
      );
    }

    // Fast-path: check if file is plain unencrypted ZIP / XLSX
    if (bytes[0] == 0x50 && bytes[1] == 0x4B) {
      return DecryptResult(
        status: DecryptStatus.notProtected,
        bytes: bytes,
      );
    }

    if (!CfbParser.isCfbFile(bytes)) {
      return DecryptResult(
        status: DecryptStatus.notProtected,
        bytes: bytes,
      );
    }

    final Map<String, Uint8List> streams;
    try {
      streams = CfbParser.extractStreams(bytes);
    } catch (e) {
      return DecryptResult(
        status: DecryptStatus.corruptedData,
        errorMessage: 'Failed to parse CFB container: $e',
      );
    }

    final encryptionInfo = streams['EncryptionInfo'];
    final encryptedPackage = streams['EncryptedPackage'];

    if (encryptionInfo == null || encryptedPackage == null) {
      return DecryptResult(
        status: DecryptStatus.notProtected,
        bytes: bytes,
      );
    }

    if (encryptionInfo.length < 4) {
      return const DecryptResult(
        status: DecryptStatus.corruptedData,
        errorMessage: 'EncryptionInfo stream is truncated.',
      );
    }

    if (password.isEmpty) {
      return const DecryptResult(
        status: DecryptStatus.invalidPassword,
        errorMessage: 'Password cannot be empty.',
      );
    }

    final bd = ByteData.sublistView(encryptionInfo);
    final vMinor = bd.getUint16(2, Endian.little);

    Uint8List? decrypted;
    try {
      if (vMinor == 2) {
        // Standard Encryption (ECMA-376)
        decrypted = StandardDecryptor.decryptPackage(
          encryptionInfoBytes: encryptionInfo,
          encryptedPackageBytes: encryptedPackage,
          password: password,
        );
      } else if (vMinor == 4) {
        // Agile Encryption (Office 2013-365)
        decrypted = AgileDecryptor.decryptPackage(
          encryptionInfoBytes: encryptionInfo,
          encryptedPackageBytes: encryptedPackage,
          password: password,
        );
      } else {
        // Fallback: attempt both Standard and Agile
        decrypted = StandardDecryptor.decryptPackage(
          encryptionInfoBytes: encryptionInfo,
          encryptedPackageBytes: encryptedPackage,
          password: password,
        );
        decrypted ??= AgileDecryptor.decryptPackage(
          encryptionInfoBytes: encryptionInfo,
          encryptedPackageBytes: encryptedPackage,
          password: password,
        );
      }
    } catch (e) {
      return DecryptResult(
        status: DecryptStatus.corruptedData,
        errorMessage: 'Decryption failed due to an internal error: $e',
      );
    }

    if (decrypted != null) {
      return DecryptResult(
        status: DecryptStatus.success,
        bytes: decrypted,
      );
    }

    return const DecryptResult(
      status: DecryptStatus.invalidPassword,
      errorMessage: 'Incorrect password or unsupported encryption parameters.',
    );
  }
}
