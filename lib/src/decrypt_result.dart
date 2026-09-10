import 'dart:typed_data';

/// The status resulting from a decryption attempt.
enum DecryptStatus {
  /// The file was successfully decrypted into raw unencrypted OOXML ZIP bytes.
  success,

  /// The provided file is not password protected. Original bytes are preserved.
  notProtected,

  /// The provided password was incorrect or password verification failed.
  invalidPassword,

  /// The file encryption format or version is not supported.
  unsupportedFormat,

  /// The file is corrupted, truncated, or does not adhere to the CFB / OOXML specification.
  corruptedData,
}

/// The result of an Excel decryption operation.
class DecryptResult {
  /// The status code of the decryption attempt.
  final DecryptStatus status;

  /// The decrypted (or original unencrypted) bytes on success, or null on failure.
  final Uint8List? bytes;

  /// An optional descriptive error message when decryption fails.
  final String? errorMessage;

  /// Whether the decryption succeeded or the file was already unprotected.
  bool get isSuccess => status == DecryptStatus.success;

  /// Creates a new [DecryptResult].
  const DecryptResult({
    required this.status,
    this.bytes,
    this.errorMessage,
  });

  @override
  String toString() {
    return 'DecryptResult(status: $status, bytesLength: ${bytes?.length}, errorMessage: $errorMessage)';
  }
}
