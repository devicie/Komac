use std::{
    collections::BTreeSet,
    io,
    io::{Read, Seek, SeekFrom},
    mem,
};

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{Result, bail};
use inquire::{MultiSelect, min_length};
use tracing::debug;
use winget_types::installer::{
    Installer, InstallerType, NestedInstallerFiles, PortableCommandAlias,
};
use zip::ZipArchive;

use super::super::Analyzer;
use crate::prompts::{handle_inquire_error, text::optional_prompt};

const VALID_NESTED_FILE_EXTENSIONS: [&str; 6] =
    ["msix", "msi", "appx", "exe", "msixbundle", "appxbundle"];

const IGNORABLE_FOLDERS: [&str; 2] = ["__MACOSX", "resources"];

pub struct Zip<R: Read + Seek> {
    archive: ZipArchive<R>,
    pub possible_installer_files: Vec<Utf8PathBuf>,
    pub installers: Vec<Installer>,
}

impl<R: Read + Seek> Zip<R> {
    pub fn new(reader: R) -> Result<Self> {
        let mut zip = ZipArchive::new(reader)?;

        let possible_installer_files = zip
            .file_names()
            .map(Utf8Path::new)
            .filter(|file_name| {
                VALID_NESTED_FILE_EXTENSIONS.iter().any(|file_extension| {
                    file_name
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case(file_extension))
                })
            })
            .filter(|file_name| {
                // Ignore folders that the main executable is unlikely to be in
                file_name.components().all(|component| {
                    IGNORABLE_FOLDERS
                        .iter()
                        .all(|folder| !component.as_str().eq_ignore_ascii_case(folder))
                })
            })
            .map(Utf8Path::to_path_buf)
            .collect::<Vec<_>>();

        debug!(?possible_installer_files);

        if possible_installer_files.is_empty() {
            bail!("ZIP contains no valid installer files (exe, msi, msix, appx, etc.)");
        }

        let mut nested_installer_files = BTreeSet::new();
        let mut installers = None;
        let exe_candidates = possible_installer_files
            .iter()
            .filter(|file_name| {
                file_name
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
            })
            .collect::<Vec<_>>();
        let has_non_exe_candidates = possible_installer_files.iter().any(|file_name| {
            file_name
                .extension()
                .is_some_and(|extension| !extension.eq_ignore_ascii_case("exe"))
        });
        let chosen_file_name = if possible_installer_files.len() == 1 {
            possible_installer_files.first()
        } else if exe_candidates.len() > 1 && !has_non_exe_candidates {
            // For ZIPs containing only portable EXEs, pick the one with the fewest folder levels.
            exe_candidates.iter().copied().min_by_key(|p| p.components().count())
        } else {
            None
        };

        if let Some(chosen_file_name) = chosen_file_name {
            nested_installer_files = BTreeSet::from([NestedInstallerFiles {
                relative_file_path: (*chosen_file_name).clone(),
                portable_command_alias: None,
            }]);
            if let Ok(mut chosen_file) = zip.by_name(chosen_file_name.as_str()) {
                let mut temp_file = tempfile::tempfile()?;
                io::copy(&mut chosen_file, &mut temp_file)?;
                temp_file.seek(SeekFrom::Start(0))?;
                let file_analyzer = Analyzer::new(&mut temp_file, chosen_file_name.as_str())?;
                installers = Some(
                    file_analyzer
                        .installers
                        .into_iter()
                        .map(|installer| Installer {
                            r#type: Some(InstallerType::Zip),
                            nested_installer_type: installer
                                .r#type
                                .and_then(|installer_type| installer_type.try_into().ok()),
                            nested_installer_files: nested_installer_files.clone(),
                            ..installer
                        })
                        .collect::<Vec<_>>(),
                );
            }
        }

        Ok(Self {
            archive: zip,
            possible_installer_files,
            installers: installers.unwrap_or_else(|| {
                vec![Installer {
                    r#type: Some(InstallerType::Zip),
                    nested_installer_files,
                    ..Installer::default()
                }]
            }),
        })
    }

    pub fn prompt(&mut self) -> Result<()> {
        if !&self.possible_installer_files.is_empty() {
            let chosen = MultiSelect::new(
                "Select the nested files",
                mem::take(&mut self.possible_installer_files),
            )
            .with_validator(min_length!(1))
            .prompt()
            .map_err(handle_inquire_error)?;
            let first_choice = chosen.first().unwrap();
            let mut temp_file = tempfile::tempfile()?;
            io::copy(
                &mut self.archive.by_name(first_choice.as_str())?,
                &mut temp_file,
            )?;
            temp_file.seek(SeekFrom::Start(0))?;
            let file_analyzer = Analyzer::new(&mut temp_file, first_choice.file_name().unwrap())?;
            let nested_installer_files = chosen
                .into_iter()
                .map(|path| {
                    Ok(NestedInstallerFiles {
                        portable_command_alias: if file_analyzer.installers[0].r#type
                            == Some(InstallerType::Portable)
                        {
                            optional_prompt::<PortableCommandAlias, &str>(None, None)?
                        } else {
                            None
                        },
                        relative_file_path: path,
                    })
                })
                .collect::<Result<BTreeSet<_>>>()?;
            self.installers = file_analyzer
                .installers
                .into_iter()
                .map(|installer| Installer {
                    nested_installer_type: installer
                        .r#type
                        .and_then(|installer_type| installer_type.try_into().ok()),
                    nested_installer_files: nested_installer_files.clone(),
                    ..installer
                })
                .collect();
        }
        Ok(())
    }
}
