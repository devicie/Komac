use std::io::{Cursor, Read, Seek, SeekFrom};

use memmap2::Mmap;
use sevenz_rust2::{ArchiveReader, Password};
use thiserror::Error;
use tracing::debug;
use winget_types::installer::{Installer, InstallerType};
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

        // TODO surely there's a better way to carve out the config
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

        let mut archive_start = end_pos + CONFIG_END.len();
        while data.get(archive_start) == Some(&0x0d) || data.get(archive_start) == Some(&0x0a) {
            archive_start += 1;
        }

        let mut archive =
            ArchiveReader::new(Cursor::new(&data[archive_start..]), Password::empty())?;
        let program_data = archive.read_file(&run_program)?;

        let mut temp = tempfile::tempfile()?;
        std::io::Write::write_all(&mut temp, &program_data)?;
        let mmap = unsafe { Mmap::map(&temp) }?;

        let mut installers = Analyzer::new(&mmap, &run_program)?.installers;

        // InstallAware uses exe bootstrapper with MSI
        if installers[0].r#type == Some(InstallerType::Portable)
            && run_program.to_lowercase().ends_with(".exe")
        {
            let msi_program = format!("{}.msi", &run_program[..run_program.len() - 4]);
            debug!(
                "No installers found in {}, trying {}",
                run_program, msi_program
            );

            if let Ok(msi_data) = archive.read_file(&msi_program) {
                let mut msi_temp = tempfile::tempfile()?;
                std::io::Write::write_all(&mut msi_temp, &msi_data)?;
                let msi_mmap = unsafe { Mmap::map(&msi_temp) }?;

                if let Ok(msi_analyzer) = Analyzer::new(&msi_mmap, &msi_program) {
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
