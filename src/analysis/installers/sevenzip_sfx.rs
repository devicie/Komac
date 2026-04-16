use std::io::{Cursor, Read, Seek, SeekFrom};

use camino::Utf8Path;
use sevenz_rust2::{ArchiveReader, Password};
use thiserror::Error;
use tracing::debug;
use winget_types::installer::{Installer, InstallerType};

use crate::analysis::{Analyzer, Installers, installers::pe::PE};

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
            pe.overlay_offset()
                .ok_or(SevenZipSfxError::NotSevenZipSfx)?,
        ))?;

        // TODO surely there's a better way to carve out the config
        let mut buf = vec![0u8; CONFIG_START.len()];
        reader
            .read_exact(&mut buf)
            .map_err(|_| SevenZipSfxError::NotSevenZipSfx)?;
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
                line.trim().strip_prefix("RunProgram=").map(|v| {
                    let v = v.trim_matches('"').trim_start_matches("\\\"");
                    let v = v.split("\\\"").next().unwrap_or(v);
                    let v = v.split_whitespace().next().unwrap_or(v);
                    let mut v = v.to_owned();
                    while v.contains("\\\\") {
                        v = v.replace("\\\\", "\\");
                    }
                    v.strip_prefix(".\\")
                        .or_else(|| v.strip_prefix("%%T\\"))
                        .or_else(|| v.strip_prefix("%T\\"))
                        .unwrap_or(&v)
                        .to_owned()
                })
            })
            .ok_or(SevenZipSfxError::NoRunProgram)?;

        debug!(run_program);

        let archive_start = end_pos
            + CONFIG_END.len()
            + data[end_pos + CONFIG_END.len()..]
                .iter()
                .take_while(|&&b| b == 0x0d || b == 0x0a)
                .count();

        let mut archive =
            ArchiveReader::new(Cursor::new(&data[archive_start..]), Password::empty())?;
        let program_data = archive.read_file(&run_program)?;

        let mut cursor = Cursor::new(program_data);
        let mut installers = Analyzer::new(&mut cursor, &run_program)?.installers;

        // InstallAware uses exe bootstrapper with MSI
        if installers[0].r#type == Some(InstallerType::Portable)
            && run_program.to_lowercase().ends_with(".exe")
        {
            let msi_program = Utf8Path::new(&run_program)
                .with_extension("msi")
                .into_string();
            debug!(
                "No installers found in {}, trying {}",
                run_program, msi_program
            );

            if let Ok(msi_data) = archive.read_file(&msi_program) {
                let mut msi_cursor = Cursor::new(msi_data);
                if let Ok(msi_analyzer) = Analyzer::new(&mut msi_cursor, &msi_program) {
                    installers = msi_analyzer.installers;
                }
            }
        }

        Ok(Self { installers })
    }
}

impl Installers for SevenZipSfx {
    fn installers(&self) -> Vec<Installer> {
        self.installers.clone()
    }
}
