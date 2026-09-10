# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-11

### Added
- Initial release of `excel_decryptor`.
- Pure-Dart detection of password-protected Microsoft Office Excel (`.xlsx`) and OOXML files via `ExcelDecryptor.isProtected`.
- Pure-Dart decryption supporting ECMA-376 Agile Encryption (AES-128/256-CBC with SHA-1, SHA-256, SHA-384, SHA-512).
- Pure-Dart decryption supporting ECMA-376 Standard Encryption (AES-128-ECB with SHA-1).
- Dynamic sector size handling in `CfbParser` for both CFB v3 (512-byte) and CFB v4 (4096-byte) containers.
- Simple synchronous API (`ExcelDecryptor.decrypt`) and detailed result API (`ExcelDecryptor.decryptWithResult`).
- Comprehensive unit test suite with real banking and Office 365 spreadsheet fixtures.
- Standalone CLI example script in `example/example.dart`.
