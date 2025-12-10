mod file;
mod setup_ini;

use std::{
    collections::BTreeSet,
    ffi::CStr,
    io::{Read, Seek, SeekFrom},
};

use byteorder::{LittleEndian, ReadBytesExt};
use encoding_rs::{Encoding, UTF_16LE};
use msi::Language;
use thiserror::Error;
use tracing::debug;
use winget_types::{
    LanguageTag,
    installer::{
        AppsAndFeaturesEntry, Architecture, ExpectedReturnCodes, InstallModes, Installer,
        InstallerReturnCode, InstallerSwitches, InstallerType, ReturnResponse, Scope,
    },
};
use yara_x::mods::PE;

use crate::{
    analysis::{
        Installers,
        installers::installshield::{file::File, setup_ini::SetupIni},
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
}

impl InstallShield {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, InstallShieldError> {
        let header_offset = pe
            .overlay
            .offset
            .ok_or(InstallShieldError::NotInstallShieldFile)?;

        // Seek to the header
        reader
            .seek(SeekFrom::Start(header_offset))
            .map_err(|_| InstallShieldError::NotInstallShieldFile)?;

        let header = Header::read(&mut reader)?;

        debug!(?header);

        let files = match header.kind {
            Kind::Plain => parse_plain_entries(&mut reader, header.num_files)?,
            Kind::SetupStream => {
                parse_stream_entries(&mut reader, header.num_files, header.header_type)?
            }
        };

        let setup_ini = extract_setup_ini(&mut reader, &files)?;

        Ok(Self {
            architecture: Architecture::from_machine(pe.machine()),
            setup_ini,
        })
    }
}

impl Installers for InstallShield {
    fn installers(&self) -> Vec<Installer> {
        let product_code = format!(
            "InstallShield_{}",
            self.setup_ini.startup.product_code.clone()
        );
        let upgrade_code = self.setup_ini.startup.upgrade_code.clone();
        let display_name = self.setup_ini.startup.product.clone();
        let publisher = self.setup_ini.startup.company_name.clone();
        let display_version = self.setup_ini.startup.product_version.clone();
        let primary_language_id = u16::from_str_radix(
            &self.setup_ini.languages.default.trim_start_matches("0x"),
            16,
        )
        .unwrap();

        let installer = Installer {
            locale: Language::from_code(primary_language_id)
                .tag()
                .parse::<LanguageTag>()
                .ok(),
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            scope: Some(Scope::Machine),
            product_code: Some(product_code.clone()),
            apps_and_features_entries: AppsAndFeaturesEntry::builder()
                .display_name(display_name)
                .maybe_publisher(publisher)
                .display_version(display_version)
                .product_code(product_code.clone())
                .maybe_upgrade_code(upgrade_code)
                .build()
                .into(),
            install_modes: InstallModes::all(),
            switches: InstallerSwitches::builder()
                .silent("/S /V/quiet /V/norestart".parse().unwrap())
                .silent_with_progress("/S /V/passive /V/norestart".parse().unwrap())
                .install_location("/V\"INSTALLDIR=\"\"<INSTALLPATH>\"\"\"".parse().unwrap())
                .log("/V\"/log \"\"<LOGPATH>\"\"\"".parse().unwrap())
                .build(),
            expected_return_codes: BTreeSet::from([
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(-1),
                    return_response: ReturnResponse::CancelledByUser,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1),
                    return_response: ReturnResponse::InvalidParameter,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1150),
                    return_response: ReturnResponse::SystemNotSupported,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1201),
                    return_response: ReturnResponse::DiskFull,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1203),
                    return_response: ReturnResponse::InvalidParameter,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1601),
                    return_response: ReturnResponse::ContactSupport,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1602),
                    return_response: ReturnResponse::CancelledByUser,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1618),
                    return_response: ReturnResponse::InstallInProgress,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1623),
                    return_response: ReturnResponse::SystemNotSupported,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1625),
                    return_response: ReturnResponse::BlockedByPolicy,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1628),
                    return_response: ReturnResponse::InvalidParameter,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1633),
                    return_response: ReturnResponse::SystemNotSupported,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1638),
                    return_response: ReturnResponse::AlreadyInstalled,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1639),
                    return_response: ReturnResponse::InvalidParameter,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1641),
                    return_response: ReturnResponse::RebootInitiated,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1640),
                    return_response: ReturnResponse::BlockedByPolicy,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1643),
                    return_response: ReturnResponse::BlockedByPolicy,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1644),
                    return_response: ReturnResponse::BlockedByPolicy,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1649),
                    return_response: ReturnResponse::BlockedByPolicy,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1650),
                    return_response: ReturnResponse::InvalidParameter,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(1654),
                    return_response: ReturnResponse::SystemNotSupported,
                    return_response_url: None,
                },
                ExpectedReturnCodes {
                    installer_return_code: InstallerReturnCode::new(3010),
                    return_response: ReturnResponse::RebootRequiredToFinish,
                    return_response_url: None,
                },
            ]),
            ..Installer::default()
        };

        vec![installer]
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

fn extract_setup_ini<R: Read + Seek>(
    reader: &mut R,
    files: &[File],
) -> Result<SetupIni, InstallShieldError> {
    for file in files.iter().rev() {
        if !file.name.eq_ignore_ascii_case("setup.ini") {
            continue;
        }
        let Some(data) = file.decrypt(reader)? else {
            continue;
        };
        let content = if let Some((encoding, bom_len)) = Encoding::for_bom(&data) {
            encoding.decode(&data[bom_len..]).0.into_owned()
        } else {
            std::str::from_utf8(&data)
                .map(String::from)
                .unwrap_or_else(|_| UTF_16LE.decode(&data).0.into_owned())
        };
        debug!(content);
        return Ok(serini::from_str::<SetupIni>(&content)?);
    }
    Err(InstallShieldError::NotInstallShieldFile)
}
