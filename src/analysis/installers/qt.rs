use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
};

use byteorder::{BigEndian, ReadBytesExt};
use serde::Deserialize;
use thiserror::Error;
use winget_types::{
    Version,
    installer::{
        AppsAndFeaturesEntries, AppsAndFeaturesEntry, Architecture, ExpectedReturnCodes,
        InstallModes, Installer, InstallerReturnCode, InstallerSwitches, InstallerType,
        ReturnResponse,
    },
};
use yara_x::mods::PE;

use crate::{analysis::Installers, traits::FromMachine};

#[derive(Error, Debug)]
pub enum QtError {
    #[error("Not a Qt Installer Framework installer")]
    NotQtFile,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Updates")]
struct Updates {
    #[serde(rename = "ApplicationName")]
    application_name: Option<String>,
    #[serde(rename = "ApplicationVersion")]
    application_version: Option<String>,
    #[serde(rename = "PackageUpdate")]
    package_updates: Option<Vec<PackageUpdate>>,
}

#[derive(Debug, Deserialize)]
struct PackageUpdate {
    #[serde(rename = "DisplayName")]
    display_name: Option<String>,
    #[serde(rename = "Version")]
    version: Option<String>,
}

pub struct Qt {
    architecture: Architecture,
    updates: Updates,
}

impl Qt {
    // Detects Qt Installer Framework (IFW) by parsing Updates.xml from the PE overlay's QT resource (qres)
    // Installer config.xml has Publisher and DefaultInstallDirectory, but we'd need to traverse the file tree
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, QtError> {
        let overlay_offset = pe.overlay.offset.ok_or(QtError::NotQtFile)?;

        reader.seek(SeekFrom::Start(overlay_offset))?;

        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"qres" {
            return Err(QtError::NotQtFile);
        }

        reader.seek(SeekFrom::Current(8))?; // Skip version and tree_offset
        let data_offset = reader.read_u32::<BigEndian>()?;

        reader.seek(SeekFrom::Start(overlay_offset + u64::from(data_offset)))?;

        let size = reader.read_u32::<BigEndian>()? as usize;
        let mut data = vec![0u8; size];
        reader.read_exact(&mut data)?;

        let updates: Updates =
            quick_xml::de::from_str(std::str::from_utf8(&data).map_err(|_| QtError::NotQtFile)?)
                .map_err(|_| QtError::NotQtFile)?;

        Ok(Self {
            architecture: Architecture::from_machine(pe.machine()),
            updates,
        })
    }
}

impl Installers for Qt {
    fn installers(&self) -> Vec<Installer> {
        let package = self
            .updates
            .package_updates
            .as_ref()
            .and_then(|p| p.first());

        let display_name = self
            .updates
            .application_name
            .clone()
            .or_else(|| package.and_then(|p| p.display_name.clone()));

        let version = self
            .updates
            .application_version
            .clone()
            .or_else(|| package.and_then(|p| p.version.clone()));

        vec![Installer {
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            install_modes: InstallModes::all(),
            switches: InstallerSwitches::builder()
                .silent(
                    "install --accept-licenses --accept-messages --confirm-command --default-answer"
                        .parse()
                        .unwrap(),
                )
                .silent_with_progress(
                    "install --accept-licenses --accept-messages --confirm-command --default-answer"
                        .parse()
                        .unwrap(),
                )
                .install_location("--root \"<INSTALLPATH>\"".parse().unwrap())
                .build(),
            expected_return_codes: expected_return_codes(),
            apps_and_features_entries: AppsAndFeaturesEntries::from(
                AppsAndFeaturesEntry::builder()
                    .maybe_display_name(display_name)
                    .maybe_display_version(version.and_then(|v| v.parse::<Version>().ok()))
                    .build(),
            ),
            ..Installer::default()
        }]
    }
}

// https://doc.qt.io/qtinstallerframework/qinstaller-packagemanagercore.html#Status-enum
fn expected_return_codes() -> BTreeSet<ExpectedReturnCodes> {
    use ReturnResponse::*;
    [
        (1, ContactSupport),
        (2, InstallInProgress),
        (3, CancelledByUser),
    ]
    .into_iter()
    .map(|(code, response)| ExpectedReturnCodes {
        installer_return_code: InstallerReturnCode::new(code),
        return_response: response,
        return_response_url: None,
    })
    .collect()
}
