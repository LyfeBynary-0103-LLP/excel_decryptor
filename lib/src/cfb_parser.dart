import 'dart:math';
import 'dart:typed_data';

/// Magic signature for Microsoft Compound File Binary (CFB) format: 0xD0CF11E0A1B11AE1.
const List<int> cfbHeaderSignature = <int>[
  0xD0,
  0xCF,
  0x11,
  0xE0,
  0xA1,
  0xB1,
  0x1A,
  0xE1,
];

const int _endOfChain = -2;

/// A parsed stream or storage entry inside an OLE Compound File.
class CfbEntry {
  /// The decoded UTF-16 entry name.
  String name = '';

  /// The entry type (1 = user storage, 2 = user stream, 5 = root storage).
  int type = 0;

  /// Starting sector location in the FAT / MiniFAT chain.
  int start = 0;

  /// Stream size in bytes.
  int size = 0;

  /// Directory index of the left sibling node.
  int leftSibling = -1;

  /// Directory index of the right sibling node.
  int rightSibling = -1;

  /// Directory index of the child node.
  int child = -1;

  /// The raw content bytes if extracted.
  Uint8List? content;

  /// Creates an empty CFB directory entry.
  CfbEntry();
}

/// Parser for Microsoft Compound File Binary (CFB / OLE2) containers.
/// Used to extract [EncryptionInfo] and [EncryptedPackage] streams from password-protected Office files.
class CfbParser {
  /// Checks whether the given [bytes] start with the OLE CFB header signature.
  static bool isCfbFile(Uint8List bytes) {
    if (bytes.length < 8) return false;
    for (int i = 0; i < 8; i++) {
      if (bytes[i] != cfbHeaderSignature[i]) return false;
    }
    return true;
  }

  /// Parses a CFB container and extracts named streams into a map of stream name to byte array.
  /// Dynamically supports both CFB v3 (512-byte sectors) and CFB v4 (4096-byte sectors).
  static Map<String, Uint8List> extractStreams(Uint8List file) {
    if (file.length < 512) {
      throw ArgumentError('CFB file size must be at least 512 bytes');
    }
    if (!isCfbFile(file)) {
      throw ArgumentError('Not a valid Compound File Binary format');
    }

    final byteData = ByteData.sublistView(file);

    // Read dynamic sector shift at byte offset 30: 9 for 512B (v3), 12 for 4096B (v4)
    final sectorShift = byteData.getUint16(30, Endian.little);
    final int sectorSize;
    if (sectorShift >= 9 && sectorShift <= 16) {
      sectorSize = 1 << sectorShift;
    } else {
      final majorVersion = byteData.getUint16(26, Endian.little);
      sectorSize = majorVersion == 4 ? 4096 : 512;
    }

    // Read dynamic mini-sector shift at byte offset 32: typically 6 for 64B
    final miniSectorShift = byteData.getUint16(32, Endian.little);
    final int miniSectorSize;
    if (miniSectorShift >= 1 && miniSectorShift <= 12) {
      miniSectorSize = 1 << miniSectorShift;
    } else {
      miniSectorSize = 64;
    }

    // Read mini-stream cutoff at byte offset 56: typically 4096
    final miniStreamCutoff = byteData.getUint32(56, Endian.little);
    final int effectiveCutoff = miniStreamCutoff > 0 ? miniStreamCutoff : 4096;

    final dirStart = byteData.getInt32(48, Endian.little);
    final miniFatStart = byteData.getInt32(60, Endian.little);
    final numMiniFatSectors = byteData.getInt32(64, Endian.little);
    final difatStart = byteData.getInt32(68, Endian.little);
    final numDifatSectors = byteData.getInt32(72, Endian.little);

    // Initial 109 FAT sector locations from header (starting at offset 76)
    final fatAddrs = <int>[];
    for (int j = 0; j < 109; j++) {
      final q = byteData.getInt32(76 + j * 4, Endian.little);
      if (q < 0) break;
      fatAddrs.add(q);
    }

    // Split file into sectors (sector 0 starts at offset sectorSize)
    final sectors = <Uint8List>[];
    final totalSectors = (file.length / sectorSize).ceil() - 1;
    for (int i = 1; i < totalSectors; i++) {
      sectors.add(file.sublist(i * sectorSize, (i + 1) * sectorSize));
    }
    if (totalSectors * sectorSize < file.length) {
      sectors.add(file.sublist(totalSectors * sectorSize));
    }

    // Follow DIFAT chain if more than 109 FAT sectors exist
    _readDifat(difatStart, numDifatSectors, sectors, sectorSize, fatAddrs);

    // Read Directory entries
    final entries = <CfbEntry>[];
    final dirBytes = _readSectorChain(sectors, dirStart, fatAddrs, sectorSize);
    final dirByteData = ByteData.sublistView(dirBytes);

    int miniStreamStart = _endOfChain;

    for (int offset = 0; offset + 128 <= dirBytes.length; offset += 128) {
      final nameLen = dirByteData.getUint16(offset + 64, Endian.little);
      if (nameLen <= 2) continue;

      final nameBytes = dirBytes.sublist(offset, offset + nameLen - 2);
      final name = _decodeUtf16le(nameBytes);

      final entry = CfbEntry()
        ..name = name
        ..type = dirByteData.getUint8(offset + 66)
        ..leftSibling = dirByteData.getInt32(offset + 68, Endian.little)
        ..rightSibling = dirByteData.getInt32(offset + 72, Endian.little)
        ..child = dirByteData.getInt32(offset + 76, Endian.little)
        ..start = dirByteData.getInt32(offset + 116, Endian.little)
        ..size = dirByteData.getInt32(offset + 120, Endian.little);

      if (entry.type == 5) {
        // Root storage entry holds mini-stream starting sector
        miniStreamStart = entry.start;
      }
      entries.add(entry);
    }

    // Read Mini-FAT stream if mini-streams exist
    Uint8List? miniFatData;
    if (numMiniFatSectors > 0 && miniFatStart != _endOfChain) {
      miniFatData =
          _readSectorChain(sectors, miniFatStart, fatAddrs, sectorSize);
    }

    // Read Mini-Stream container from Root entry
    Uint8List? miniStreamData;
    if (miniStreamStart != _endOfChain) {
      miniStreamData =
          _readSectorChain(sectors, miniStreamStart, fatAddrs, sectorSize);
    }

    // Extract streams
    final result = <String, Uint8List>{};
    for (final entry in entries) {
      if (entry.type != 2) continue; // Only stream entries

      if (entry.size >= effectiveCutoff) {
        // Stored in standard FAT sectors
        final data =
            _readSectorChain(sectors, entry.start, fatAddrs, sectorSize);
        final len = min(entry.size, data.length);
        result[entry.name] = data.sublist(0, len);
      } else if (miniStreamData != null &&
          miniFatData != null &&
          entry.start != _endOfChain) {
        // Stored in Mini-FAT sectors
        final data = _readMiniSectorChain(
          miniStreamData,
          miniFatData,
          entry.start,
          entry.size,
          miniSectorSize,
        );
        result[entry.name] = data;
      }
    }

    return result;
  }

  static void _readDifat(
    int idx,
    int count,
    List<Uint8List> sectors,
    int sectorSize,
    List<int> fatAddrs,
  ) {
    if (idx == _endOfChain || count <= 0 || idx < 0 || idx >= sectors.length) {
      return;
    }
    final sector = sectors[idx];
    final bd = ByteData.sublistView(sector);
    final entriesPerSector = (sectorSize >> 2) - 1;

    for (int i = 0; i < entriesPerSector; i++) {
      final addr = bd.getInt32(i * 4, Endian.little);
      if (addr == _endOfChain || addr < 0) break;
      fatAddrs.add(addr);
    }

    final nextDifat = bd.getInt32(sectorSize - 4, Endian.little);
    _readDifat(nextDifat, count - 1, sectors, sectorSize, fatAddrs);
  }

  static Uint8List _readSectorChain(
    List<Uint8List> sectors,
    int startSector,
    List<int> fatAddrs,
    int sectorSize,
  ) {
    final chain = <Uint8List>[];
    int current = startSector;
    final modulus = sectorSize - 1;
    final seen = <int>{};

    while (
        current >= 0 && current < sectors.length && !seen.contains(current)) {
      seen.add(current);
      chain.add(sectors[current]);

      final fatSectorIndex = (current * 4) ~/ sectorSize;
      if (fatSectorIndex >= fatAddrs.length) break;

      final fatSectorAddr = fatAddrs[fatSectorIndex];
      if (fatSectorAddr < 0 || fatSectorAddr >= sectors.length) break;

      final offset = (current * 4) & modulus;
      final bd = ByteData.sublistView(sectors[fatSectorAddr]);
      current = bd.getInt32(offset, Endian.little);
      if (current == _endOfChain) break;
    }

    final totalLen =
        chain.fold<int>(0, (int sum, Uint8List s) => sum + s.length);
    final result = Uint8List(totalLen);
    int pos = 0;
    for (final s in chain) {
      result.setRange(pos, pos + s.length, s);
      pos += s.length;
    }
    return result;
  }

  static Uint8List _readMiniSectorChain(
    Uint8List miniStream,
    Uint8List miniFat,
    int startSector,
    int size,
    int miniSectorSize,
  ) {
    final chunks = <Uint8List>[];
    int current = startSector;
    int remaining = size;
    final bd = ByteData.sublistView(miniFat);
    final seen = <int>{};

    while (current >= 0 && remaining > 0 && !seen.contains(current)) {
      seen.add(current);
      final offset = current * miniSectorSize;
      if (offset + miniSectorSize <= miniStream.length) {
        final chunkLen = min(remaining, miniSectorSize);
        chunks.add(miniStream.sublist(offset, offset + chunkLen));
        remaining -= chunkLen;
      } else {
        break;
      }

      if (current * 4 + 4 <= miniFat.length) {
        current = bd.getInt32(current * 4, Endian.little);
      } else {
        break;
      }
      if (current == _endOfChain) break;
    }

    final totalLen =
        chunks.fold<int>(0, (int sum, Uint8List c) => sum + c.length);
    final result = Uint8List(totalLen);
    int pos = 0;
    for (final c in chunks) {
      result.setRange(pos, pos + c.length, c);
      pos += c.length;
    }
    return result;
  }

  static String _decodeUtf16le(Uint8List bytes) {
    final codeUnits = <int>[];
    for (int i = 0; i + 1 < bytes.length; i += 2) {
      codeUnits.add(bytes[i] | (bytes[i + 1] << 8));
    }
    return String.fromCharCodes(codeUnits);
  }
}
