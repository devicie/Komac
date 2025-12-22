mod nuspec;

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use nuspec::NuSpec;
use quick_xml::de::from_str;
use thiserror::Error;
use tracing::debug;
use winget_types::installer::{
    AppsAndFeaturesEntry, Architecture, InstallationMetadata, Installer, InstallerSwitches,
    InstallerType, Scope,
};
use yara_x::mods::PE;
use zip::ZipArchive;

use crate::{analysis::Installers, traits::FromMachine};

#[derive(Error, Debug)]
pub enum SquirrelError {
    #[error("File is not a Squirrel installer")]
    NotSquirrelFile,
    #[error("No nupkg found in Squirrel zip")]
    NoNupkgFound,
    #[error("No nuspec found in nupkg")]
    NoNuspecFound,
    #[error(transparent)]
    NuspecDeserialization(#[from] quick_xml::DeError),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct Squirrel {
    pub architecture: Architecture,
    pub nuspec: NuSpec,
}

impl Squirrel {
    pub fn new<R: Read + Seek>(mut reader: R, pe: &PE) -> Result<Self, SquirrelError> {
        let resource = pe.resources.first().ok_or(SquirrelError::NotSquirrelFile)?;

        reader.seek(SeekFrom::Start(resource.offset().into()))?;
        let mut zip_data = Vec::new();
        reader
            .take(resource.length().into())
            .read_to_end(&mut zip_data)?;
        let mut zip = ZipArchive::new(Cursor::new(zip_data))?;

        let nupkg_name = zip
            .file_names()
            .find(|name| name.ends_with(".nupkg"))
            .map(String::from)
            .ok_or(SquirrelError::NoNupkgFound)?;
        let mut nupkg_data = Vec::new();
        zip.by_name(&nupkg_name)?.read_to_end(&mut nupkg_data)?;
        let mut nupkg = ZipArchive::new(Cursor::new(nupkg_data))?;

        let nuspec_name = nupkg
            .file_names()
            .find(|name| name.ends_with(".nuspec"))
            .map(String::from)
            .ok_or(SquirrelError::NoNuspecFound)?;
        let nuspec_data = io::read_to_string(nupkg.by_name(&nuspec_name)?)?;
        debug!(%nuspec_data);
        let nuspec: NuSpec = from_str(&nuspec_data)?;

        let entrypoint = nupkg
            .file_names()
            .filter(|name| name.ends_with(".exe"))
            .find(|name| {
                name.rsplit('/')
                    .next()
                    .and_then(|f| f.strip_suffix(".exe"))
                    .is_some_and(|stem| {
                        stem.eq_ignore_ascii_case(&nuspec.metadata.id)
                            || stem.eq_ignore_ascii_case(&nuspec.metadata.title)
                    })
            })
            .map(String::from);
        let architecture = entrypoint
            .and_then(|name| {
                let mut exe_data = Vec::new();
                nupkg.by_name(&name).ok()?.read_to_end(&mut exe_data).ok()?;
                yara_x::mods::invoke::<PE>(&exe_data)
                    .map(|pe| Architecture::from_machine(pe.machine()))
            })
            .unwrap_or_else(|| Architecture::from_machine(pe.machine()));

        Ok(Self {
            architecture,
            nuspec,
        })
    }
}

impl Installers for Squirrel {
    fn installers(&self) -> Vec<Installer> {
        let metadata = &self.nuspec.metadata;

        vec![Installer {
            architecture: self.architecture,
            r#type: Some(InstallerType::Exe),
            scope: Some(Scope::User),
            product_code: Some(metadata.id.clone()),
            apps_and_features_entries: AppsAndFeaturesEntry::builder()
                .display_name(metadata.title.clone())
                .publisher(metadata.authors.clone())
                .display_version(metadata.version.clone())
                .product_code(metadata.id.clone())
                .build()
                .into(),
            switches: InstallerSwitches::builder()
                .silent("--silent".parse().unwrap())
                .silent_with_progress("--silent".parse().unwrap())
                .build(),
            installation_metadata: InstallationMetadata {
                default_install_location: Some(camino::Utf8PathBuf::from(format!(
                    "%LocalAppData%\\{}",
                    metadata.id
                ))),
                ..InstallationMetadata::default()
            },
            ..Installer::default()
        }]
    }
}
