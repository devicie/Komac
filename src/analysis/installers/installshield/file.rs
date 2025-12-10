use std::io::{Read, Seek, SeekFrom};

use flate2::bufread::ZlibDecoder;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FileError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct File {
    pub name: String,
    pub encoded_flags: u32,
    pub size: u32,
    pub offset: u64,
}

impl File {
    pub fn decrypt<R: Read + Seek>(&self, reader: &mut R) -> Result<Option<Vec<u8>>, FileError> {
        const FLAG_ENCODED: u32 = 0x2;
        const FLAG_CHUNKED: u32 = 0x4;
        const XOR_MAGIC: [u8; 4] = [0x13, 0x35, 0x86, 0x07];
        const CHUNK_SIZE: usize = 1024;

        if self.encoded_flags & (FLAG_ENCODED | FLAG_CHUNKED) == 0 {
            return Ok(None);
        }

        reader.seek(SeekFrom::Start(self.offset))?;
        let mut data = vec![0u8; self.size as usize];
        reader.read_exact(&mut data)?;

        let key: Vec<u8> = self
            .name
            .bytes()
            .enumerate()
            .map(|(i, b)| b ^ XOR_MAGIC[i % XOR_MAGIC.len()])
            .collect();
        if key.is_empty() {
            return Ok(None);
        }

        if self.encoded_flags & FLAG_CHUNKED != 0 {
            for chunk in data.chunks_mut(CHUNK_SIZE) {
                decode_slice(chunk, &key, 0);
            }
        } else {
            decode_slice(&mut data, &key, 0);
        }

        let mut decompressed = Vec::new();
        if ZlibDecoder::new(data.as_slice())
            .read_to_end(&mut decompressed)
            .is_ok()
        {
            return Ok(Some(decompressed));
        }

        Ok(Some(data))
    }
}

fn decode_slice(data: &mut [u8], key: &[u8], key_offset: usize) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = !(key[(key_offset + i) % key.len()] ^ byte.rotate_left(4));
    }
}
