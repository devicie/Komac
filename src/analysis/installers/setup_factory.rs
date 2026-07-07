use std::io::{Read, Seek};

use thiserror::Error;
use winget_types::installer::{
    Architecture, InstallModes, Installer, InstallerSwitches, InstallerType,
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
}

impl SetupFactory {
    // Detects Indigo Rose Setup Factory installers. The setup stub embeds `irsetup.exe`, whose
    // assembly manifest carries `<description>Setup Factory Run-time</description>`, and the builder
    // stamps `Created with Setup Factory <version>` into the `Comments` version-info field.
    //
    // The stub's version info describes the run-time (or is left at Setup Factory's defaults), not
    // the packaged application, and the registry uninstall entry (`DisplayName`, `DisplayVersion`,
    // `ProductCode`, ...) is written by the compiled setup script inside the payload. Neither is
    // reliably recoverable here, so no `AppsAndFeaturesEntries` are emitted rather than guessing
    // from the version info.
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, SetupFactoryError> {
        let is_runtime_manifest = pe
            .manifest(&mut reader)
            .is_ok_and(|manifest| manifest.contains(RUNTIME_DESCRIPTION));

        let has_setup_factory_comments =
            pe.vs_version_info(&mut reader).ok().is_some_and(|bytes| {
                VSVersionInfo::read_from(&bytes).is_ok_and(|info| {
                    info.string_table()
                        .get("Comments")
                        .is_some_and(|comments| comments.contains(COMMENTS_MARKER))
                })
            });

        if !is_runtime_manifest && !has_setup_factory_comments {
            return Err(SetupFactoryError::NotSetupFactoryFile);
        }

        Ok(Self {
            architecture: Architecture::from_machine(pe.machine()),
        })
    }
}

impl Installers for SetupFactory {
    fn installers(&self) -> Vec<Installer> {
        vec![Installer {
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            install_modes: InstallModes::all(),
            // https://www.indigorose.com/webhelp/suf9/Program_Reference/Command_Line_Options.htm
            switches: InstallerSwitches::builder()
                .silent("/S".parse().unwrap())
                .silent_with_progress("/S".parse().unwrap())
                .build(),
            ..Installer::default()
        }]
    }
}
