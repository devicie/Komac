use std::io::{Read, Seek};

use color_eyre::Result;
use inno::{Inno, error::InnoError};
use tracing::debug;
use winget_types::installer::{Installer, InstallerSwitches, InstallerType};

use super::{super::Installers, AdvancedInstaller, Burn, InstallShield, Nsis, Squirrel};
use crate::{
    analysis::installers::{
        advanced::AdvancedInstallerError,
        burn::BurnError,
        installshield::InstallShieldError,
        nsis::NsisError,
        pe::{PE, VSVersionInfo},
        squirrel::SquirrelError,
    },
    traits::IntoWingetArchitecture,
};

const ORIGINAL_FILENAME: &str = "OriginalFilename";
const FILE_DESCRIPTION: &str = "FileDescription";
const BASIC_INSTALLER_KEYWORDS: [&str; 4] = ["installer", "setup", "7zs.sfx", "7zsd.sfx"];

pub struct Exe {
    r#type: ExeType,
    pub legal_copyright: Option<String>,
    pub product_name: Option<String>,
    pub company_name: Option<String>,
}

pub enum ExeType {
    AdvancedInstaller(AdvancedInstaller),
    Burn(Box<Burn>),
    Inno(Box<Inno>),
    InstallShield(InstallShield),
    Nsis(Nsis),
    Squirrel(Squirrel),
    Generic(Box<Installer>),
}

impl Exe {
    pub fn new<R: Read + Seek>(mut reader: R) -> Result<Self> {
        let pe = PE::read_from(&mut reader)?;

        let vs_version_info_bytes = pe.vs_version_info(&mut reader).ok();
        let vs_version_info = vs_version_info_bytes
            .as_deref()
            .and_then(|version_info_bytes| VSVersionInfo::read_from(version_info_bytes).ok());
        let mut string_table = vs_version_info.as_ref().map(VSVersionInfo::string_table);
        let legal_copyright = string_table
            .as_mut()
            .and_then(|table| table.swap_remove("LegalCopyright"))
            .map(str::to_owned);
        let product_name = string_table
            .as_mut()
            .and_then(|table| table.swap_remove("ProductName"))
            .map(str::to_owned);
        let company_name = string_table
            .as_mut()
            .and_then(|table| table.swap_remove("CompanyName"))
            .map(str::to_owned);

        match AdvancedInstaller::new(&mut reader, &pe) {
            Ok(advanced) => {
                return Ok(Self {
                    r#type: ExeType::AdvancedInstaller(advanced),
                    legal_copyright,
                    product_name,
                    company_name,
                });
            }
            Err(AdvancedInstallerError::NotAdvancedInstallerFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Burn::new(&mut reader, &pe) {
            Ok(burn) => {
                return Ok(Self {
                    r#type: ExeType::Burn(Box::new(burn)),
                    legal_copyright,
                    product_name,
                    company_name,
                });
            }
            Err(BurnError::NotBurnFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Inno::new(&mut reader) {
            Ok(inno) => {
                return Ok(Self {
                    r#type: ExeType::Inno(Box::new(inno)),
                    legal_copyright,
                    product_name,
                    company_name,
                });
            }
            Err(InnoError::NotInnoFile) => {}
            Err(error) => return Err(error.into()),
        }

        match InstallShield::new(&mut reader, &pe) {
            Ok(installshield) => {
                return Ok(Self {
                    r#type: ExeType::InstallShield(installshield),
                    legal_copyright,
                    product_name,
                    company_name,
                });
            }
            Err(InstallShieldError::NotInstallShieldFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Nsis::new(&mut reader, &pe) {
            Ok(nsis) => {
                return Ok(Self {
                    r#type: ExeType::Nsis(nsis),
                    legal_copyright,
                    product_name,
                    company_name,
                });
            }
            Err(NsisError::NotNsisFile) => {}
            Err(error) => return Err(error.into()),
        }

        match Squirrel::new(&mut reader, &pe) {
            Ok(squirrel) => {
                return Ok(Self {
                    r#type: ExeType::Squirrel(squirrel),
                    legal_copyright,
                    product_name,
                    company_name,
                });
            }
            Err(SquirrelError::NotSquirrelFile) => {}
            Err(error) => return Err(error.into()),
        }

        let internal_name = string_table
            .as_ref()
            .and_then(|table| table.get("InternalName").copied())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let silent = match internal_name.as_str() {
            // Setup.exe is used by several installer types, so we can't determine its args
            "sfxcab.exe" => "/quiet",
            "7zs.sfx" | "7z.sfx" | "7zsd.sfx" => "/s",
            "setup launcher" => "/s",
            "wextract" => "/Q",
            _ => "",
        };

        if pe.find_section(*b"UPX0\0\0\0\0").is_some() {
            debug!("Detected UPX packed exe");
        }

        Ok(Self {
            r#type: ExeType::Generic(Box::new(Installer {
                architecture: pe.winget_architecture(),
                r#type: if string_table.is_some_and(|mut table| {
                    let original_filename = table.swap_remove(ORIGINAL_FILENAME);
                    let file_description = table.swap_remove(FILE_DESCRIPTION);

                    BASIC_INSTALLER_KEYWORDS.iter().any(|keyword| {
                        original_filename.is_some_and(|filename| filename.contains(keyword))
                            || file_description
                                .is_some_and(|description| description.contains(keyword))
                    })
                }) {
                    Some(InstallerType::Exe)
                } else {
                    Some(InstallerType::Portable)
                },
                switches: if !silent.is_empty() {
                    InstallerSwitches::builder()
                        .silent(silent.parse().unwrap())
                        .silent_with_progress(silent.parse().unwrap())
                        .build()
                } else {
                    InstallerSwitches::default()
                },
                ..Installer::default()
            })),
            legal_copyright,
            product_name,
            company_name,
        })
    }
}

impl Installers for Exe {
    fn installers(&self) -> Vec<Installer> {
        match &self.r#type {
            ExeType::AdvancedInstaller(advanced) => advanced.installers(),
            ExeType::Burn(burn) => burn.installers(),
            ExeType::Inno(inno) => inno.installers(),
            ExeType::InstallShield(installshield) => installshield.installers(),
            ExeType::Nsis(nsis) => nsis.installers(),
            ExeType::Squirrel(squirrel) => squirrel.installers(),
            ExeType::Generic(installer) => vec![*installer.clone()],
        }
    }
}
