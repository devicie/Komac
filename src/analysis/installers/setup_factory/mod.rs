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
    metadata: ScriptMetadata,
}

impl SetupFactory {
    // Detects Indigo Rose Setup Factory installers. The setup stub embeds `irsetup.exe`, whose
    // assembly manifest carries `<description>Setup Factory Run-time</description>`, and the builder
    // stamps `Created with Setup Factory <version>` into the `Comments` version-info field.
    //
    // Rather than guess the packaged application's details from the stub's version info (which
    // describes the run-time, and is often left at Setup Factory's defaults), the Setup Factory 8/9
    // archive in the PE overlay is walked to recover the compiled setup script and its session
    // variable table - the real product name, publisher and version the author entered.
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, SetupFactoryError> {
        let overlay_start = pe.overlay_offset();

        let has_archive =
            overlay_start.is_some_and(|start| has_archive_signature(&mut reader, start));

        // The overlay signature is the definitive marker, but fall back to the run-time manifest and
        // version-info comments so older (Setup Factory 7) or repacked stubs are still recognised.
        if !has_archive
            && !is_runtime_manifest(pe, &mut reader)
            && !has_setup_factory_comments(pe, &mut reader)
        {
            return Err(SetupFactoryError::NotSetupFactoryFile);
        }

        let metadata = overlay_start
            .filter(|_| has_archive)
            .and_then(|start| archive::read_script(&mut reader, start).ok().flatten())
            .map(|script| ScriptMetadata::parse(&script))
            .unwrap_or_default();

        debug!(?metadata, "Setup Factory");

        Ok(Self {
            architecture: Architecture::from_machine(pe.machine()),
            metadata,
        })
    }
}

fn has_archive_signature<R: Read + Seek>(reader: &mut R, overlay_start: u64) -> bool {
    if reader.seek(SeekFrom::Start(overlay_start)).is_err() {
        return false;
    }
    let mut signature = [0; archive::SIGNATURE.len()];
    reader.read_exact(&mut signature).is_ok() && signature == archive::SIGNATURE
}

fn is_runtime_manifest<R: Read + Seek>(pe: &PE, reader: &mut R) -> bool {
    pe.manifest(reader)
        .is_ok_and(|manifest| manifest.contains(RUNTIME_DESCRIPTION))
}

fn has_setup_factory_comments<R: Read + Seek>(pe: &PE, reader: &mut R) -> bool {
    pe.vs_version_info(reader).ok().is_some_and(|bytes| {
        VSVersionInfo::read_from(&bytes).is_ok_and(|info| {
            info.string_table()
                .get("Comments")
                .is_some_and(|comments| comments.contains(COMMENTS_MARKER))
        })
    })
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
