mod file;
mod return_codes;
mod setup_ini;
mod setup_iss;

use std::{
    ffi::CStr,
    io::{Read, Seek, SeekFrom},
};

use byteorder::{LittleEndian, ReadBytesExt};
use encoding_rs::UTF_16LE;
use msi::Language;
use thiserror::Error;
use tracing::debug;
use winget_types::{
    LanguageTag,
    installer::{
        AppsAndFeaturesEntry, Architecture, InstallModes, Installer, InstallerSwitches,
        InstallerType, Scope,
    },
};
use yara_x::mods::PE;

use crate::{
    analysis::{
        Installers,
        installers::installshield::{file::File, setup_ini::SetupIni, setup_iss::SetupIss},
    },
    traits::FromMachine,
};

pub use file::FileError;

#[derive(Error, Debug)]
pub enum InstallShieldError {
    #[error("File is not an InstallShield installer")]
    NotInstallShieldFile,
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Ini(#[from] serini::Error),
}

#[derive(Debug)]
pub struct InstallShield {
    pub architecture: Architecture,
    pub setup_ini: SetupIni,
    pub setup_iss: Option<SetupIss>,
}

impl InstallShield {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, InstallShieldError> {
        let header_offset = pe
            .overlay
            .offset
            .ok_or(InstallShieldError::NotInstallShieldFile)?;

        reader
            .seek(SeekFrom::Start(header_offset))
            .map_err(|_| InstallShieldError::NotInstallShieldFile)?;

        let files = if pe
            .version_info
            .get("ISInternalDescription")
            .is_some_and(|desc| desc.starts_with("InstallScript"))
        {
            parse_installscript_entries(&mut reader)?
        } else {
            let header = Header::read(&mut reader)?;
            debug!(?header);
            let files = match header.kind {
                Kind::Plain => parse_plain_entries(&mut reader, header.num_files)?,
                Kind::SetupStream => {
                    parse_stream_entries(&mut reader, header.num_files, header.header_type)?
                }
            };
            files
        };

        let setup_ini = files
            .iter()
            .rev()
            .find(|f| f.name.eq_ignore_ascii_case("setup.ini"))
            .and_then(|f| {
                let content = f.read_text(&mut reader).ok()??;
                debug!("{}", content);
                serini::from_str::<SetupIni>(&content).ok()
            })
            .ok_or(InstallShieldError::NotInstallShieldFile)?;

        let setup_iss = files
            .iter()
            .rev()
            .find(|f| f.name.eq_ignore_ascii_case("setup.iss"))
            .and_then(|f| {
                let content = f.read_text(&mut reader).ok()??;
                debug!("{}", content);
                serini::from_str::<SetupIss>(&content).ok()
            });

        Ok(Self {
            architecture: Architecture::from_machine(pe.machine()),
            setup_ini,
            setup_iss,
        })
    }
}

impl Installers for InstallShield {
    fn installers(&self) -> Vec<Installer> {
        let startup = &self.setup_ini.startup;
        let publisher = startup
            .company_name
            .as_ref()
            .or_else(|| self.setup_iss.as_ref().map(|iss| &iss.application.company));
        let product_code = startup
            .product_code
            .as_ref()
            .map(|code| format!("InstallShield_{code}"))
            .or_else(|| {
                startup
                    .product_guid
                    .as_ref()
                    .map(|guid| format!("{{{guid}}}"))
            });
        let version = startup
            .product_version
            .as_ref()
            .or_else(|| self.setup_iss.as_ref().map(|iss| &iss.application.version));
        let locale = u16::from_str_radix(
            self.setup_ini.languages.default.trim_start_matches("0x"),
            16,
        )
        .ok()
        .and_then(|id| Language::from_code(id).tag().parse::<LanguageTag>().ok());

        vec![Installer {
            locale,
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            scope: Some(Scope::Machine),
            product_code: product_code.clone(),
            apps_and_features_entries: AppsAndFeaturesEntry::builder()
                .display_name(startup.product.clone())
                .maybe_publisher(publisher)
                .maybe_display_version(version)
                .maybe_product_code(product_code)
                .maybe_upgrade_code(startup.upgrade_code.clone())
                .build()
                .into(),
            install_modes: InstallModes::all(),
            switches: InstallerSwitches::builder()
                .silent("/S /V/quiet /V/norestart".parse().unwrap())
                .silent_with_progress("/S /V/passive /V/norestart".parse().unwrap())
                .install_location("/V\"INSTALLDIR=\"\"<INSTALLPATH>\"\"\"".parse().unwrap())
                .log("/V\"/log \"\"<LOGPATH>\"\"\"".parse().unwrap())
                .build(),
            expected_return_codes: return_codes::expected_return_codes(),
            ..Installer::default()
        }]
    }
}

#[derive(Debug)]
struct Header {
    kind: Kind,
    num_files: u16,
    header_type: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    SetupStream,
}

impl Header {
    fn read<R: Read + Seek>(reader: &mut R) -> Result<Self, InstallShieldError> {
        // Skip optional PDB 2.0 info (NB10 signature)
        let mut sig = [0u8; 4];
        reader.read_exact(&mut sig)?;
        if &sig == b"NB10" {
            reader.seek(SeekFrom::Current(12))?;
            while reader.read_u8()? != 0 {}
        } else {
            reader.seek(SeekFrom::Current(-4))?;
        }

        let mut magic = [0u8; 14];
        reader.read_exact(&mut magic)?;
        let num_files = reader.read_u16::<LittleEndian>()?;
        let header_type = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(26))?; // reserved
        let kind = match CStr::from_bytes_until_nul(&magic)
            .ok()
            .and_then(|c| c.to_str().ok())
        {
            Some("InstallShield") => Kind::Plain,
            Some("ISSetupStream") => Kind::SetupStream,
            _ => return Err(InstallShieldError::NotInstallShieldFile),
        };

        Ok(Self {
            kind,
            num_files,
            header_type,
        })
    }
}

fn parse_plain_entries<R: Read + Seek>(
    reader: &mut R,
    count: u16,
) -> Result<Vec<File>, InstallShieldError> {
    let mut files = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut raw_name = [0u8; 260]; // MAX_PATH
        reader.read_exact(&mut raw_name)?;
        let encoded_flags = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(4))?; // reserved
        let size = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(40))?; // 8 + 2 + 30 reserved

        let name = CStr::from_bytes_until_nul(&raw_name)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_default();
        let offset = reader.stream_position()?;
        reader.seek(SeekFrom::Current(i64::from(size)))?;

        files.push(File {
            name,
            encoded_flags,
            size,
            offset,
        });
    }
    Ok(files)
}

fn parse_stream_entries<R: Read + Seek>(
    reader: &mut R,
    count: u16,
    header_type: u32,
) -> Result<Vec<File>, InstallShieldError> {
    let mut files = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let filename_len = reader.read_u32::<LittleEndian>()?;
        let encoded_flags = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(2))?; // reserved
        let size = reader.read_u32::<LittleEndian>()?;
        reader.seek(SeekFrom::Current(10))?; // 8 + 2 reserved
        if header_type == 4 {
            reader.seek(SeekFrom::Current(24))?; // attributes
        }

        let name = if filename_len == 0 {
            String::new()
        } else {
            let mut buffer = vec![0u8; filename_len as usize];
            reader.read_exact(&mut buffer)?;
            UTF_16LE.decode(&buffer).0.trim_matches('\0').to_owned()
        };
        let offset = reader.stream_position()?;
        reader.seek(SeekFrom::Current(i64::from(size)))?;

        files.push(File {
            name,
            encoded_flags,
            size,
            offset,
        });
    }

    Ok(files)
}

fn parse_installscript_entries<R: Read + Seek>(
    reader: &mut R,
) -> Result<Vec<File>, InstallShieldError> {
    (0..reader.read_u32::<LittleEndian>()?)
        .map(|_| {
            let name = read_utf16le_strz(reader)?;
            for _ in 0..2 {
                read_utf16le_strz(reader)?;
            }
            let size: u32 = read_utf16le_strz(reader)?.parse().unwrap_or(0);
            let offset = reader.stream_position()?;
            reader.seek(SeekFrom::Current(i64::from(size)))?;
            Ok(File {
                name,
                encoded_flags: 0,
                size,
                offset,
            })
        })
        .collect()
}

fn read_utf16le_strz<R: Read>(reader: &mut R) -> Result<String, std::io::Error> {
    let mut buf = Vec::new();
    loop {
        let code_unit = reader.read_u16::<LittleEndian>()?;
        if code_unit == 0 {
            break;
        }
        buf.extend_from_slice(&code_unit.to_le_bytes());
    }
    Ok(UTF_16LE.decode(&buf).0.into_owned())
}
