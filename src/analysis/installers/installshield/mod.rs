mod file;
mod return_codes;
mod setup_ini;
mod setup_iss;
mod setup_xml;

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
        AppsAndFeaturesEntry, Architecture, InstallModes, InstallationMetadata, Installer,
        InstallerSwitches, InstallerType, Scope,
    },
};
use yara_x::mods::PE;

use crate::{
    analysis::{
        Installers,
        installers::{
            installshield::{
                file::File, setup_ini::SetupIni, setup_iss::SetupIss, setup_xml::SetupXml,
            },
            utils::RELATIVE_PROGRAM_FILES_64,
        },
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
    pub setup_ini: Option<SetupIni>,
    pub setup_iss: Option<SetupIss>,
    pub setup_xml: Option<SetupXml>,
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

        // TODO instead, try parsing each type and skip if it fails?
        let files = if pe
            .version_info
            .get("ISInternalDescription")
            .is_some_and(|desc| desc.starts_with("InstallScript"))
        {
            let file_count = reader.read_u32::<LittleEndian>()?;
            parse_installscript_entries(&mut reader, file_count, read_utf16le_strz)?
        } else if pe
            .version_info
            .get("ProductName")
            .is_some_and(|name| name == "InstallShield (R)")
        {
            parse_installscript_entries(&mut reader, u32::MAX, read_ascii_strz)?
        } else {
            let header = Header::read(&mut reader)?;
            debug!(?header);
            match header.kind {
                Kind::Plain => parse_plain_entries(&mut reader, header.num_files)?,
                Kind::SetupStream => {
                    parse_stream_entries(&mut reader, header.num_files, header.header_type)?
                }
            }
        };
        files.iter().for_each(|f| debug!(?f.name));

        let setup_ini = find_and_parse(&files, &mut reader, "setup.ini", |content| {
            serini::from_str::<SetupIni>(content).ok()
        });

        let setup_iss = find_and_parse(&files, &mut reader, "setup.iss", |content| {
            serini::from_str::<SetupIss>(content).ok()
        });

        let setup_xml = find_and_parse(&files, &mut reader, "Setup.xml", |content| {
            quick_xml::de::from_str::<SetupXml>(content).ok()
        });

        if setup_ini.is_none() && setup_iss.is_none() && setup_xml.is_none() {
            return Err(InstallShieldError::NotInstallShieldFile);
        }

        Ok(Self {
            architecture: Architecture::from_machine(pe.machine()),
            setup_ini,
            setup_iss,
            setup_xml,
        })
    }
}

fn find_and_parse<R: Read + Seek, T>(
    files: &[File],
    reader: &mut R,
    name: &str,
    parse: fn(&str) -> Option<T>,
) -> Option<T> {
    files
        .iter()
        .rev()
        .find(|f| f.name.eq_ignore_ascii_case(name))
        .and_then(|f| match f.read_text(reader) {
            Ok(Some(content)) => {
                debug!("{content}");
                let result = parse(&content);
                if result.is_none() {
                    debug!("Failed to parse {}", f.name);
                }
                result
            }
            Ok(None) => None,
            Err(e) => {
                debug!("Failed to read {}: {e}", f.name);
                None
            }
        })
}

impl Installers for InstallShield {
    fn installers(&self) -> Vec<Installer> {
        let startup = self.setup_ini.as_ref().map(|ini| &ini.startup);
        let xml = self.setup_xml.as_ref();
        let iss = self.setup_iss.as_ref();
        let script_driven = startup.and_then(|s| s.script_driven.as_deref());
        let msi_based = matches!(script_driven, Some("0" | "2"));

        if script_driven == Some("4") && iss.is_none() {
            tracing::warn!(
                "InstallScriptUnicode installer without embedded setup.iss - \
                 a separate response file may be required for silent installation: \
                 https://github.com/microsoft/winget-pkgs/issues/246"
            );
        }

        let publisher = startup
            .and_then(|s| s.company_name.as_deref())
            .or_else(|| iss.map(|iss| iss.application.company.as_str()))
            .or_else(|| {
                xml.and_then(|xml| {
                    xml.languages
                        .language
                        .iter()
                        .find(|lang| lang.lcid == xml.language_selection.default)
                        .and_then(|lang| {
                            lang.strings
                                .get(&xml.arp_info.publisher)
                                .map(|s| s.as_str())
                        })
                        .or(Some(xml.arp_info.publisher.as_str()))
                })
            });

        let product_code = startup
            .and_then(|s| s.product_code.as_ref())
            .map(|code| {
                if msi_based {
                    code.clone()
                } else if script_driven == Some("4") {
                    format!("{{{code}}}")
                } else {
                    format!("InstallShield_{code}")
                }
            })
            .or_else(|| {
                xml.and_then(|xml| {
                    xml.get_property("ProductCode")
                        .or_else(|| Some(xml.suite_id.clone()))
                })
            });

        let version = startup
            .and_then(|s| s.product_version.as_deref())
            .or_else(|| iss.map(|iss| iss.application.version.as_str()))
            .or_else(|| xml.map(|xml| xml.arp_info.version.as_str()));

        let locale = self
            .setup_ini
            .as_ref()
            .and_then(|ini| {
                u16::from_str_radix(ini.languages.default.trim_start_matches("0x"), 16).ok()
            })
            .or_else(|| xml.and_then(|xml| xml.language_selection.default.parse().ok()))
            .and_then(|id| Language::from_code(id).tag().parse::<LanguageTag>().ok());

        let display_name = startup
            .and_then(|s| s.product.clone())
            .or_else(|| iss.map(|iss| iss.application.name.clone()))
            .or_else(|| xml.map(|xml| xml.arp_info.display_name.clone()))
            .or_else(|| xml.and_then(|xml| xml.get_property("ProductName")));

        let upgrade_code = startup
            .and_then(|s| s.upgrade_code.clone())
            .or_else(|| xml.and_then(|xml| xml.get_property("UpgradeCode")));

        // TODO are these MSI vars? could reuse logic from burn/manifest/variable.rs
        let install_dir = xml
            .and_then(|xml| xml.get_property("INSTALLDIR"))
            .map(|v| v.replace("[ProgramFiles64Folder]", RELATIVE_PROGRAM_FILES_64));

        let scope = install_dir
            .as_deref()
            .and_then(Scope::from_install_directory)
            .or(Some(Scope::Machine));

        let switches = if xml.is_some() {
            // Suite/Advanced UI
            InstallerSwitches::builder()
                .silent("/silent".parse().unwrap())
                .silent_with_progress("/passive".parse().unwrap())
                .log("/log \"<LOGPATH>\"".parse().unwrap())
                .repair("/repair".parse().unwrap())
                .build()
        } else if msi_based {
            // Basic MSI or Basic MSI with InstallScript
            InstallerSwitches::builder()
                .silent("/s /v\"/qn /norestart\"".parse().unwrap())
                .silent_with_progress("/s /v\"/qb /norestart\"".parse().unwrap())
                .install_location("/v\"INSTALLDIR=\"\"<INSTALLPATH>\"\"\"".parse().unwrap())
                .log("/v\"/log \"\"<LOGPATH>\"\"\"".parse().unwrap())
                .build()
        } else {
            // InstallScript
            InstallerSwitches::builder()
                .silent("/s".parse().unwrap())
                .silent_with_progress("/s".parse().unwrap())
                .build()
        };

        vec![Installer {
            locale,
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            scope,
            product_code: product_code.clone(),
            apps_and_features_entries: AppsAndFeaturesEntry::builder()
                .maybe_display_name(display_name)
                .maybe_publisher(publisher)
                .maybe_display_version(version)
                .maybe_product_code(product_code)
                .maybe_upgrade_code(upgrade_code)
                .build()
                .into(),
            installation_metadata: InstallationMetadata {
                default_install_location: install_dir.map(camino::Utf8PathBuf::from),
                ..InstallationMetadata::default()
            },
            install_modes: InstallModes::all(),
            switches,
            expected_return_codes: return_codes::expected_return_codes(msi_based),
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
    count: u32,
    read: fn(&mut R) -> Result<String, std::io::Error>,
) -> Result<Vec<File>, InstallShieldError> {
    let start = reader.stream_position()?;
    let end = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(start))?;
    let mut files = Vec::new();
    while files.len() < count as usize && reader.stream_position()? < end {
        let name = read(reader)?;
        if name.is_empty() {
            break;
        }
        read(reader)?; // path
        read(reader)?; // version
        let size: u32 = read(reader)?.parse().unwrap_or(0);
        let offset = reader.stream_position()?;
        reader.seek(SeekFrom::Current(i64::from(size)))?;
        files.push(File {
            name,
            encoded_flags: 0,
            size,
            offset,
        });
    }
    Ok(files)
}

fn read_ascii_strz<R: Read>(reader: &mut R) -> Result<String, std::io::Error> {
    let mut buf = Vec::new();
    loop {
        let byte = reader.read_u8()?;
        if byte == 0 {
            break;
        }
        buf.push(byte);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
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
