# InstallShield Setup Format

## Overview

InstallShield installers are self-extracting PE executables containing compressed installation files. The installer data is appended after the PE sections.

## File Structure

```text
┌─────────────────────────────────────┐
│ PE Header + Sections                │
│ (Standard Windows Executable)       │
├─────────────────────────────────────┤
│ Optional: Version Signature         │
│ (e.g., "NB10")                      │
├─────────────────────────────────────┤
│ InstallShield Header (46 bytes)     │
│ - Signature (14 bytes)              │
│ - Number of files (2 bytes)         │
│ - Type field (4 bytes)              │
│ - Padding (26 bytes)                │
├─────────────────────────────────────┤
│ File Table (variable)               │
│ [IS 12.x or IS 30.x structure]      │
├─────────────────────────────────────┤
│ File Data (inline, encrypted/       │
│ compressed)                          │
└─────────────────────────────────────┘
```

## Header Formats

### Main Header (46 bytes)

```text
Offset  Size  Field
──────────────────────────────────────
0x00    14    Signature ("InstallShield" or "ISSetupStream")
0x0E    2     Number of files (uint16)
0x10    4     Type field (uint32)
0x14    8     x4 (unknown)
0x1C    2     x5 (unknown)
0x1E    16    x6 (unknown)
```

### Legacy Format ("InstallShield")

Uses fixed 260-byte paths and older encryption. Rare in modern installers.

### ISSetupStream Format

Modern format with two variants:

#### InstallShield 12.x File Attributes (24 bytes)

```text
Offset  Size  Field
──────────────────────────────────────
0x00    4     Filename length in bytes (UTF-16)
0x04    4     Encoded flags
0x08    2     x3 (unknown)
0x0A    4     File length
0x0E    8     x5 (unknown)
0x16    2     is_unicode_launcher
```

#### InstallShield 30.x+ File Attributes (48 bytes)

```text
Offset  Size  Field
──────────────────────────────────────
0x00    4     Filename length in bytes (UTF-16)
0x04    4     x2 (typically 6, unknown purpose)
0x08    4     Encoded flags
0x0C    4     File length
0x10    8     x3 (unknown/padding)
0x18    8     Timestamp 1 (FILETIME)
0x20    8     Timestamp 2 (FILETIME)
0x28    8     Timestamp 3 (FILETIME)
```

**Note**: IS 30.x has TWO `ISSetupStream` headers:

1. First header at data section start
2. Second header marking the file table location

## File Storage

Files are stored **inline** with no offset table:

```text
┌─────────────────────────────────────┐
│ File Attributes (24 or 48 bytes)    │
├─────────────────────────────────────┤
│ Filename (UTF-16, variable length)  │
├─────────────────────────────────────┤
│ File Data (encrypted/compressed)    │
│ [Variable length, no delimiter]     │
├─────────────────────────────────────┤
│ File Attributes (next file)         │
├─────────────────────────────────────┤
│ Filename (UTF-16)                   │
├─────────────────────────────────────┤
│ File Data                           │
└─────────────────────────────────────┘
```

To find files, scan forward looking for valid file attribute structures (no offset table exists).

## Encryption & Compression

### XOR Encryption

```rust
const MAGIC_DEC: [u8; 4] = [0x13, 0x35, 0x86, 0x07];

// Key derived from filename
key = filename.bytes().collect()

// Decrypt in 1024-byte blocks
for block in data.chunks(1024) {
    for (i, byte) in block.iter_mut().enumerate() {
        *byte ^= MAGIC_DEC[i % 4];
        *byte ^= key[i % key.len()];
    }
}
```

### Flag Encoding

Flags control encryption/compression behavior:

**IS 12.x**: Flags in lower byte of `encoded_flags` (0x000000XX)
**IS 30.x**: Flags in upper byte of `encoded_flags` (0xXX000000)

```text
Flag Bits:
  0x01 - has_type_1
  0x02 - has_type_2 (block-based decoding)
  0x04 - has_type_4 (full-file decoding)
  0x08 - has_type_8
```

### Compression

After decryption, data is zlib-compressed (magic: 0x78).

```rust
// After XOR decryption
if decrypted_data[0] == 0x78 {
    // Decompress with zlib
    let mut decoder = ZlibDecoder::new(&decrypted_data[..]);
    decoder.read_to_end(&mut output)?;
}
```

## Version Detection

1. **PE Version Info**: Check `ISInternalVersion` resource (e.g., "30.0.157")
2. **MSI Package**: Read `creating_application` property
3. **Fallback**: Assume IS 12.x if no version info

```text
Major Version ≥ 30 → Use IS 30.x structures
Major Version < 30 → Use IS 12.x structures
```

## Key Files

### Setup.ini

Primary installer configuration (UTF-16 LE):

```ini
[Startup]
ProductName=Product Name
ProductVersion=1.0.0
ProductCode={GUID}
UpgradeCode={GUID}
Default=0x0409  ; Default language LCID

[0x0409]  ; English (US)
COMPANY_NAME=Company Name
PRODUCT_NAME=Product Name
; ... localized strings
```

### Language Files

Format: `0x{LCID:04x}.ini` (e.g., `0x0409.ini` for en-US, `0x0804.ini` for zh-CN)

Contains localized UI strings for the installer.

### MSI Packages

Windows Installer packages, often with language-specific transforms (`.mst` files).

## Scanning Heuristics

To find file attributes when parsing IS 30.x:

```rust
// Valid attributes must have:
- filename_len: 10-200 bytes, even (UTF-16)
- x2: 1-10 (strongly prefer 6)
- encoded_flags upper byte: not 0x00 or 0xFF
- File attributes can start at ANY byte offset (1-byte stepping required)
```

## Common Issues

1. **Header reports wrong file count**: May be off by one; stop gracefully when no more files found
2. **file_len = 0**: Common in IS 30.x; read until valid data extracted (up to 100KB)
3. **Odd byte offsets**: Files can start at non-aligned offsets (e.g., 5215); must use 1-byte stepping
4. **Language INI decoding**: May use non-UTF encodings; handle gracefully

## References

- Original C implementation: ISx.c (unshield project)
- InstallShield versions: 2010 (12.x), 30.x (modern)
- Tested with: Sonos 90.0, Trimble Connect 1.26, FedEx Ship Manager 25.01
