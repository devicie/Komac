use std::{mem, num::NonZeroUsize, str::FromStr};

use futures_util::TryFutureExt;
use itertools::Itertools;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::try_join;
use winget_types::{
    PackageIdentifier, PackageVersion,
    installer::{InstallerType, MinimumOSVersion},
    locale::ReleaseNotes,
    url::ReleaseNotesUrl,
};

use super::{
    github_configuration,
    token::resolve_github_token,
    types::{ManifestChange, UpdateVersionOptions, UpdateVersionResult},
    update_helpers::{fetch_github_values, fix_relative_paths, resolve_replace_version},
};
use crate::{
    download::Downloader,
    github::{
        client::GitHub,
        utils::{PackagePath, pull_request::pr_changes},
    },
    manifests::Url,
    match_installers::match_installers,
    traits::LocaleExt,
};

enum VersionSelector {
    Explicit(Box<PackageVersion>),
    ProductVersion,
    FileVersion,
    DisplayVersion,
}

fn parse_version_selector(version: &str) -> napi::Result<VersionSelector> {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return Err(Error::new(Status::InvalidArg, "A version is required"));
    }

    Ok(match trimmed {
        "productVersion" => VersionSelector::ProductVersion,
        "fileVersion" => VersionSelector::FileVersion,
        "displayVersion" => VersionSelector::DisplayVersion,
        value => VersionSelector::Explicit(Box::new(value.parse().map_err(|e| {
            Error::new(Status::InvalidArg, format!("Invalid package version: {e}"))
        })?)),
    })
}

/// Update an existing package version in winget-pkgs.
///
/// # Errors
///
/// Returns `InvalidArg` when provided arguments are invalid (identifier, URLs, versions, or selectors).
/// Returns `GenericFailure` when downloading installers, analyzing content, loading manifests,
/// or creating the pull request fails.
#[napi]
pub async fn update_version(options: UpdateVersionOptions) -> napi::Result<UpdateVersionResult> {
    let package_identifier: PackageIdentifier =
        options.package_identifier.parse().map_err(|e| {
            Error::new(
                Status::InvalidArg,
                format!("Invalid package identifier: {e}"),
            )
        })?;

    let version_selector = parse_version_selector(&options.version)?;

    let urls: Vec<Url> = options
        .urls
        .iter()
        .map(|u| Url::from_str(u))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid URL: {e}")))?;

    if urls.is_empty() {
        return Err(Error::new(
            Status::InvalidArg,
            "At least one URL is required",
        ));
    }

    let release_notes_url: Option<ReleaseNotesUrl> = options
        .release_notes_url
        .map(|u| u.parse())
        .transpose()
        .map_err(|e| {
            Error::new(
                Status::InvalidArg,
                format!("Invalid release notes URL: {e}"),
            )
        })?;

    let release_notes: Option<ReleaseNotes> = options
        .release_notes
        .map(ReleaseNotes::new)
        .transpose()
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid release notes: {e}")))?;

    let dry_run = options
        .dry_run
        .or_else(github_configuration::dry_run)
        .unwrap_or(false);

    let replace: Option<PackageVersion> = options
        .replace
        .map(|v| v.parse())
        .transpose()
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid replace version: {e}")))?;

    let force_font = options.font.unwrap_or_default();

    let token = resolve_github_token(options.token.as_deref())?;

    let github = GitHub::new(&token).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to create GitHub client: {e}"),
        )
    })?;

    let (versions, font) = github
        .get_versions(&package_identifier, force_font.then_some(true))
        .await
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to get versions: {e}"),
            )
        })?;

    let latest_version = versions
        .last()
        .ok_or_else(|| Error::new(Status::GenericFailure, "No versions found for package"))?;

    let downloader = Downloader::new_with_concurrent_and_progress(
        NonZeroUsize::new(num_cpus::get()).unwrap_or(NonZeroUsize::MIN),
        false,
    )
    .map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to create downloader: {e}"),
        )
    })?;

    let (mut manifests, mut github_values, mut files) = try_join!(
        github
            .get_manifests(&package_identifier, latest_version, font)
            .map_err(|e| Error::new(
                Status::GenericFailure,
                format!("Failed to get manifests: {e}")
            )),
        fetch_github_values(&github, &urls).map_err(|e| Error::new(
            Status::GenericFailure,
            format!("Failed to get GitHub values: {e}")
        )),
        downloader
            .download(urls.iter().cloned())
            .map_err(|e| Error::new(
                Status::GenericFailure,
                format!("Failed to download installers: {e}")
            )),
    )?;

    let mut download_results = {
        use std::collections::HashMap;

        use winget_types::{installer::Architecture, url::DecodedUrl};

        use crate::analysis::Analyzer;

        let mut results = HashMap::new();
        for file in &mut files {
            let mut file_analyzer =
                Analyzer::new(&mut file.file, &file.file_name).map_err(|e| {
                    Error::new(
                        Status::GenericFailure,
                        format!("Failed to analyze file: {e}"),
                    )
                })?;
            if let (Some(zip), Some(installer_matches)) =
                (&mut file_analyzer.zip, options.installer_matches.as_ref())
                && !installer_matches.is_empty()
            {
                let matched_analysis = zip
                    .analyze_matches_with_metadata(installer_matches)
                    .map_err(|e| {
                        Error::new(
                            Status::GenericFailure,
                            format!("Failed to analyze matching ZIP installers: {e}"),
                        )
                    })?;

                if let Some(file_version) = matched_analysis
                    .iter()
                    .filter_map(|analysis| analysis.file_version.as_deref())
                    .map(str::trim)
                    .find(|value| !value.is_empty())
                {
                    file_analyzer.file_version = Some(file_version.to_owned());
                }

                if let Some(product_version) = matched_analysis
                    .iter()
                    .filter_map(|analysis| analysis.product_version.as_deref())
                    .map(str::trim)
                    .find(|value| !value.is_empty())
                {
                    file_analyzer.product_version = Some(product_version.to_owned());
                }

                file_analyzer.installers = matched_analysis
                    .into_iter()
                    .map(|analysis| analysis.installer)
                    .collect();
            }
            let architecture = file
                .url
                .override_architecture()
                .or_else(|| Architecture::from_url(file.url.as_str()));
            for installer in &mut file_analyzer.installers {
                if let Some(architecture) = architecture {
                    installer.architecture = architecture;
                }
                installer.url = file.url.inner().clone();
                installer.sha_256 = file.sha_256.clone();
                installer.release_date = file.last_modified;
            }
            file_analyzer.file_name = mem::take(&mut file.file_name);
            let url_key: DecodedUrl = mem::take(file.url.inner_mut());
            results.insert(url_key, file_analyzer);
        }
        results
    };

    let installer_results = download_results
        .iter_mut()
        .flat_map(|(_url, analyzer)| mem::take(&mut analyzer.installers))
        .collect::<Vec<_>>();

    let product_version = download_results
        .values()
        .filter_map(|analyzer| analyzer.product_version.as_deref())
        .map(str::trim)
        .find(|value| !value.is_empty());
    let file_version = download_results
        .values()
        .filter_map(|analyzer| analyzer.file_version.as_deref())
        .map(str::trim)
        .find(|value| !value.is_empty());
    let display_version = installer_results
        .iter()
        .flat_map(|installer| installer.apps_and_features_entries.iter())
        .filter_map(|entry| {
            entry
                .display_version()
                .map(std::string::ToString::to_string)
        })
        .find(|value| !value.trim().is_empty());

    let package_version: PackageVersion = match version_selector {
        VersionSelector::Explicit(package_version) => *package_version,
        VersionSelector::ProductVersion => product_version
            .ok_or_else(|| {
                Error::new(
                    Status::InvalidArg,
                    "`version` was set to `productVersion`, but no ProductVersion was found during analysis",
                )
            })?
            .parse()
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid ProductVersion: {e}")))?,
        VersionSelector::FileVersion => file_version
            .ok_or_else(|| {
                Error::new(
                    Status::InvalidArg,
                    "`version` was set to `fileVersion`, but no FileVersion was found during analysis",
                )
            })?
            .parse()
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid FileVersion: {e}")))?,
        VersionSelector::DisplayVersion => display_version
            .ok_or_else(|| {
                Error::new(
                    Status::InvalidArg,
                    "`version` was set to `displayVersion`, but no DisplayVersion was found during analysis",
                )
            })?
            .parse()
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid DisplayVersion: {e}")))?,
    };

    let replace_version = resolve_replace_version(
        replace.as_ref(),
        &versions,
        latest_version,
        &package_version,
    )
    .map_err(|e| Error::new(Status::InvalidArg, e))?;

    let previous_installers = mem::take(&mut manifests.installer.installers)
        .into_iter()
        .map(|mut installer| {
            if manifests.installer.r#type.is_some() {
                installer.r#type = manifests.installer.r#type;
            }
            if manifests.installer.nested_installer_type.is_some() {
                installer.nested_installer_type = manifests.installer.nested_installer_type;
            }
            if manifests.installer.scope.is_some() {
                installer.scope = manifests.installer.scope;
            }
            installer
        })
        .collect::<Vec<_>>();

    let duplicate_urls = previous_installers
        .iter()
        .map(|installer| installer.url.clone())
        .duplicates()
        .collect::<Vec<_>>();

    manifests.default_locale.package_version = package_version.clone();
    let matched_installers = match_installers(&previous_installers, &installer_results);
    let mut installers = matched_installers
        .into_iter()
        .map(|(previous_installer, new_installer)| {
            let analyzer = &download_results[&new_installer.url];
            let installer_type = match previous_installer.r#type {
                Some(InstallerType::Portable) => previous_installer.r#type,
                _ => match new_installer.r#type {
                    Some(InstallerType::Portable) => previous_installer.r#type,
                    _ => new_installer.r#type,
                },
            };

            let previous_nested_files = previous_installer.nested_installer_files.clone();
            let previous_url = previous_installer.url.clone();
            let previous_architecture = previous_installer.architecture;

            let mut installer = new_installer.clone().merge_with(previous_installer);
            installer.r#type = installer_type;
            installer.url.clone_from(&new_installer.url);

            let nested_files_to_fix = [
                &previous_nested_files,
                &manifests.installer.nested_installer_files,
                &installer.nested_installer_files,
            ]
            .into_iter()
            .find(|files| !files.is_empty())
            .cloned();

            if let Some(nested_files) = nested_files_to_fix {
                installer.nested_installer_files =
                    fix_relative_paths(nested_files, analyzer.zip.as_ref());
            }

            if duplicate_urls.contains(&previous_url) {
                installer.architecture = previous_architecture;
            }

            for entry in &mut installer.apps_and_features_entries {
                entry.deduplicate(&manifests.default_locale);
            }
            installer
        })
        .collect::<Vec<_>>();

    if installers
        .iter()
        .flat_map(|installer| &installer.locale)
        .all_equal()
    {
        for installer in &mut installers {
            installer.locale = None;
        }
    }

    manifests.installer.locale = None;

    manifests.installer.package_version = package_version.clone();
    manifests.installer.minimum_os_version = manifests
        .installer
        .minimum_os_version
        .filter(|minimum_os_version| *minimum_os_version != MinimumOSVersion::new(10, 0, 0, 0));
    manifests.installer.installers = installers;
    manifests.installer.optimize();

    manifests.default_locale.update(
        &package_version,
        &mut github_values,
        release_notes_url.as_ref(),
    );

    if let Some(release_notes) = release_notes {
        manifests.default_locale.release_notes = Some(release_notes);
    }

    manifests.locales.iter_mut().for_each(|locale| {
        locale.update(&package_version, &mut github_values, None);
    });

    manifests.version.update(&package_version);

    let package_path = PackagePath::new(&package_identifier, Some(&package_version), None, font);
    let changes = pr_changes()
        .package_identifier(&package_identifier)
        .manifests(&manifests)
        .package_path(&package_path)
        .create()
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create PR changes: {e}"),
            )
        })?;

    if dry_run {
        return Ok(UpdateVersionResult {
            pull_request_url: None,
            changes: changes
                .iter()
                .map(|(path, content)| ManifestChange {
                    path: path.clone(),
                    content: content.clone(),
                })
                .collect(),
            package_identifier: package_identifier.to_string(),
            version: package_version.to_string(),
        });
    }

    let pull_request_url = github
        .add_version()
        .identifier(&package_identifier)
        .version(&package_version)
        .versions(&versions)
        .changes(changes.clone())
        .maybe_replace_version(replace_version)
        .issue_resolves(&[])
        .send()
        .await
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create pull request: {e}"),
            )
        })?;

    Ok(UpdateVersionResult {
        pull_request_url: Some(pull_request_url.url().to_string()),
        changes: changes
            .into_iter()
            .map(|(path, content)| ManifestChange { path, content })
            .collect(),
        package_identifier: package_identifier.to_string(),
        version: package_version.to_string(),
    })
}
