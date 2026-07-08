mod archive;
mod script;

use std::io::{Read, Seek, SeekFrom};

use script::ScriptMetadata;
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
    analysis::{Installers, installers::pe::PE},
    traits::FromMachine,
};

#[derive(Error, Debug)]
pub enum SetupFactoryError {
    #[error("File is not a Setup Factory installer")]
    NotSetupFactoryFile,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct SetupFactory {
    architecture: Architecture,
    metadata: ScriptMetadata,
}

impl SetupFactory {
    // Detects Indigo Rose Setup Factory installers from the Setup Factory 8/9 signature at the start
    // of the PE overlay, then walks the overlay archive to recover the compiled setup script and its
    // session variable table - the real product name, publisher and version the author entered.
    // (The stub's own version info describes the run-time, not the packaged application, and is often
    // left at Setup Factory's defaults, so it is not used.)
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, SetupFactoryError> {
        let overlay_start = pe
            .overlay_offset()
            .ok_or(SetupFactoryError::NotSetupFactoryFile)?;

        let mut signature = [0; archive::SIGNATURE.len()];
        if reader.seek(SeekFrom::Start(overlay_start)).is_err()
            || reader.read_exact(&mut signature).is_err()
            || signature != archive::SIGNATURE
        {
            return Err(SetupFactoryError::NotSetupFactoryFile);
        }

        let metadata = archive::read_script(&mut reader, overlay_start)
            .ok()
            .flatten()
            .map(|script| ScriptMetadata::parse(&script))
            .unwrap_or_default();

        debug!(?metadata, "Setup Factory");

        Ok(Self {
            architecture: Architecture::from_machine(pe.machine()),
            metadata,
        })
    }
}

impl Installers for SetupFactory {
    fn installers(&self) -> Vec<Installer> {
        let apps_and_features_entry = AppsAndFeaturesEntry::builder()
            .maybe_display_name(self.metadata.display_name.clone())
            .maybe_publisher(self.metadata.publisher.clone())
            .maybe_display_version(
                self.metadata
                    .display_version
                    .as_deref()
                    .and_then(|version| version.parse::<Version>().ok()),
            )
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
