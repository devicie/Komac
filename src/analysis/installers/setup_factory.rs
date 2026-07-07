use std::io::{Read, Seek};

use thiserror::Error;
use tracing::debug;
use winget_types::{
    Version,
    installer::{
        AppsAndFeaturesEntries, AppsAndFeaturesEntry, Architecture, InstallModes, Installer,
        InstallerSwitches, InstallerType,
    },
};

use crate::{
    analysis::{
        Installers,
        installers::pe::{PE, VSVersionInfo},
    },
    traits::FromMachine,
};

/// Description embedded in the assembly manifest of the Setup Factory run-time (`irsetup.exe`).
const RUNTIME_DESCRIPTION: &str = "Setup Factory Run-time";

/// Marker found in the `Comments` version-info field, e.g. `Created with Setup Factory 9.7`.
const COMMENTS_MARKER: &str = "Setup Factory";

#[derive(Error, Debug)]
pub enum SetupFactoryError {
    #[error("File is not a Setup Factory installer")]
    NotSetupFactoryFile,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct SetupFactory {
    architecture: Architecture,
    display_name: Option<String>,
    publisher: Option<String>,
    display_version: Option<Version>,
}

impl SetupFactory {
    // Detects Indigo Rose Setup Factory installers. The setup stub embeds `irsetup.exe`, whose
    // assembly manifest carries `<description>Setup Factory Run-time</description>`, and the builder
    // stamps `Created with Setup Factory <version>` into the `Comments` version-info field.
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, SetupFactoryError> {
        let is_runtime_manifest = pe
            .manifest(&mut reader)
            .is_ok_and(|manifest| manifest.contains(RUNTIME_DESCRIPTION));

        let vs_version_info_bytes = pe.vs_version_info(&mut reader).ok();
        let vs_version_info = vs_version_info_bytes
            .as_deref()
            .and_then(|bytes| VSVersionInfo::read_from(bytes).ok());
        let string_table = vs_version_info.as_ref().map(VSVersionInfo::string_table);

        let is_setup_factory = is_runtime_manifest
            || string_table.as_ref().is_some_and(|table| {
                table
                    .get("Comments")
                    .is_some_and(|comments| comments.contains(COMMENTS_MARKER))
            });

        if !is_setup_factory {
            return Err(SetupFactoryError::NotSetupFactoryFile);
        }

        let display_name = string_table
            .as_ref()
            .and_then(|table| table.get("ProductName"))
            .map(|name| (*name).to_owned());
        let publisher = string_table
            .as_ref()
            .and_then(|table| table.get("CompanyName"))
            .map(|company| (*company).to_owned());
        let display_version = string_table
            .as_ref()
            .and_then(|table| table.get("ProductVersion"))
            .and_then(|version| version.parse::<Version>().ok());

        debug!(?display_name, ?publisher, ?display_version, "Setup Factory");

        Ok(Self {
            architecture: Architecture::from_machine(pe.machine()),
            display_name,
            publisher,
            display_version,
        })
    }
}

impl Installers for SetupFactory {
    fn installers(&self) -> Vec<Installer> {
        let apps_and_features_entry = AppsAndFeaturesEntry::builder()
            .maybe_display_name(self.display_name.clone())
            .maybe_publisher(self.publisher.clone())
            .maybe_display_version(self.display_version.clone())
            .build();

        vec![Installer {
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            install_modes: InstallModes::all(),
            // https://www.indigorose.com/webhelp/suf9/Program_Reference/Command_Line_Options.htm
            switches: InstallerSwitches::builder()
                .silent("/S".parse().unwrap())
                .silent_with_progress("/S".parse().unwrap())
                .build(),
            apps_and_features_entries: if apps_and_features_entry.is_empty() {
                AppsAndFeaturesEntries::default()
            } else {
                apps_and_features_entry.into()
            },
            ..Installer::default()
        }]
    }
}
