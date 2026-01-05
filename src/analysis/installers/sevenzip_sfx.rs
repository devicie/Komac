use std::io::{Cursor, Read, Seek, SeekFrom};

use memmap2::Mmap;
use sevenz_rust2::{ArchiveReader, Password};
use thiserror::Error;
use winget_types::installer::Installer;
use yara_x::mods::PE;

use crate::analysis::{Analyzer, Installers};

const CONFIG_START: &[u8] = b";!@Install@!UTF-8!";
const CONFIG_END: &[u8] = b";!@InstallEnd@!";

#[derive(Error, Debug)]
pub enum SevenZipSfxError {
    #[error("Not a 7z SFX installer")]
    NotSevenZipSfx,
    #[error("No RunProgram in config")]
    NoRunProgram,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    SevenZ(#[from] sevenz_rust2::Error),
    #[error(transparent)]
    Analyze(#[from] color_eyre::eyre::Report),
}

pub struct SevenZipSfx {
    installers: Vec<Installer>,
}

impl SevenZipSfx {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, SevenZipSfxError> {
        reader.seek(SeekFrom::Start(
            pe.overlay.offset.ok_or(SevenZipSfxError::NotSevenZipSfx)?,
        ))?;

        let mut buf = vec![0u8; CONFIG_START.len()];
        reader.read_exact(&mut buf)?;
        if buf != CONFIG_START {
            return Err(SevenZipSfxError::NotSevenZipSfx);
        }

        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        let end_pos = data
            .windows(CONFIG_END.len())
            .position(|w| w == CONFIG_END)
            .ok_or(SevenZipSfxError::NotSevenZipSfx)?;

        let run_program = String::from_utf8_lossy(&data[..end_pos])
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("RunProgram=")
                    .map(|v| v.trim_matches('"').to_owned())
            })
            .ok_or(SevenZipSfxError::NoRunProgram)?;

        let program_data = ArchiveReader::new(
            Cursor::new(&data[end_pos + CONFIG_END.len()..]),
            Password::empty(),
        )?
        .read_file(&run_program)?;

        let mut temp = tempfile::tempfile()?;
        std::io::Write::write_all(&mut temp, &program_data)?;
        let mmap = unsafe { Mmap::map(&temp) }?;

        Ok(Self {
            installers: Analyzer::new(&mmap, &run_program)?.installers,
        })
    }
}

impl Installers for SevenZipSfx {
    fn installers(&self) -> Vec<Installer> {
        self.installers.clone()
    }
}
