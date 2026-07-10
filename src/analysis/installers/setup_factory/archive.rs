//! Walks the Setup Factory 8/9 archive stored in the PE overlay to recover the compiled setup
//! script (`irsetup.dat`).
//!
//! Layout (little-endian), based on the format documented by
//! [`sfextract`](https://github.com/CybercentreCanada/sfextract):
//!
//! ```text
//! [16] signature                (SIGNATURE)
//! [10] unknown
//! [ 8] irsetup.exe size, then that many XOR-obfuscated bytes
//! [ 4] file count               (if > 1000 it is really the size of an embedded lua5.1.dll)
//! per file:
//!   [264] NUL-terminated name
//!   [  8] size
//!   [  4] CRC-32
//!   [  4] unknown
//!   [ ..] compressed data (LZMA / LZMA2 / PKWARE, auto-detected from the first bytes)
//! ```

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use liblzma::{
    read::XzDecoder,
    stream::{Filters, Stream},
};
use zerocopy::LittleEndian;

use crate::read::ReadBytesExt;

/// Marks a Setup Factory 8/9 archive at the start of the PE overlay.
pub const SIGNATURE: [u8; 16] = [
    0xe0, 0xe0, 0xe1, 0xe1, 0xe2, 0xe2, 0xe3, 0xe3, 0xe4, 0xe4, 0xe5, 0xe5, 0xe6, 0xe6, 0xe7, 0xe7,
];

/// Bytes to skip from the overlay start to reach the first embedded file (signature + 10 unknown).
const HEADER_LENGTH: i64 = SIGNATURE.len() as i64 + 10;

/// Fixed width of a file name entry in the file table.
const FILENAME_LENGTH: usize = 264;

/// Name of the compiled setup script within the archive.
const SCRIPT_NAME: &[u8] = b"irsetup.dat";

/// After `irsetup.exe`, Setup Factory 9 stubs embed a second special file (`lua5.1.dll`) before the
/// file table, but older layouts do not. The two are told apart by reading a `u32`: a real file
/// count is small, whereas the low half of `lua5.1.dll`'s ~350 KB `u64` size is far larger. A value
/// above this threshold is therefore the DLL's size rather than a count. Every installer tested so
/// far (DIALux evo, LDraw AIOI, gloCOM, Communicator and the Locklizard Safeguard family, all Setup
/// Factory 9.5) embeds the DLL and takes this path.
const MAX_PLAUSIBLE_FILE_COUNT: u32 = 1000;

/// Reads and decompresses the `irsetup.dat` script from the archive at `overlay_start`.
///
/// Returns `Ok(None)` when the script is absent or uses an unsupported compression. Best-effort:
/// callers treat any error as "no metadata".
pub fn read_script<R: Read + Seek>(
    reader: &mut R,
    overlay_start: u64,
) -> io::Result<Option<Vec<u8>>> {
    reader.seek(SeekFrom::Start(overlay_start))?;
    reader.seek(SeekFrom::Current(HEADER_LENGTH))?;

    // Embedded irsetup.exe special file: an 8-byte size followed by that many bytes.
    skip_special_file(reader)?;

    let mut file_count = reader.read_u32::<LittleEndian>()?;
    if file_count > MAX_PLAUSIBLE_FILE_COUNT {
        // What we read was actually the size of an embedded lua5.1.dll special file.
        reader.seek(SeekFrom::Current(-(size_of::<u32>() as i64)))?;
        skip_special_file(reader)?;
        file_count = reader.read_u32::<LittleEndian>()?;
    }

    for _ in 0..file_count {
        let mut name = [0; FILENAME_LENGTH];
        reader.read_exact(&mut name)?;
        let name = &name[..name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(name.len())];

        let size = read_size(reader)?;
        reader.seek(SeekFrom::Current(size_of::<u32>() as i64))?; // CRC-32
        reader.seek(SeekFrom::Current(size_of::<u32>() as i64))?; // unknown

        if name.eq_ignore_ascii_case(SCRIPT_NAME) {
            // Bounded read that grows with the data rather than pre-allocating from the size field.
            let mut data = Vec::new();
            reader.take(size.unsigned_abs()).read_to_end(&mut data)?;
            return Ok(decompress(&data));
        }

        reader.seek(SeekFrom::Current(size))?;
    }

    Ok(None)
}

/// Skips an 8-byte size field and the bytes it describes.
fn skip_special_file<R: Read + Seek>(reader: &mut R) -> io::Result<()> {
    let size = read_size(reader)?;
    reader.seek(SeekFrom::Current(size))?;
    Ok(())
}

/// Reads an 8-byte little-endian size, clamping negatives to zero.
fn read_size<R: Read>(reader: &mut R) -> io::Result<i64> {
    let mut bytes = [0; size_of::<i64>()];
    reader.read_exact(&mut bytes)?;
    Ok(i64::from_le_bytes(bytes).max(0))
}

/// Decompresses a file whose compression is auto-detected from its leading bytes.
///
/// Handles the LZMA ("alone") and LZMA2 streams used by the setup script; returns `None` for the
/// PKWARE-compressed scripts of older Setup Factory versions and anything unrecognised.
fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    match (data.first()?, data.get(1)?) {
        // Classic LZMA "alone" stream (properties byte + dictionary size + uncompressed size).
        (0x5D, 0x00) => {
            let stream = Stream::new_lzma_decoder(u64::MAX).ok()?;
            XzDecoder::new_stream(Cursor::new(data), stream)
                .read_to_end(&mut output)
                .ok()?;
        }
        // Raw LZMA2 stream: one property byte, an 8-byte size, then the raw payload.
        (0x18, _) => {
            let mut filters = Filters::new();
            filters.lzma2_properties(&data[..1]).ok()?;
            let stream = Stream::new_raw_decoder(&filters).ok()?;
            XzDecoder::new_stream(Cursor::new(data.get(9..)?), stream)
                .read_to_end(&mut output)
                .ok()?;
        }
        _ => return None,
    }
    Some(output)
}
