use std::{num::NonZeroUsize, str::FromStr};

use napi::bindgen_prelude::*;
use napi_derive::napi;

use super::types::{
    AnalyzeInstallerResult, AppsAndFeaturesEntryAnalysis, InstallerAnalysis,
    NestedInstallerFileAnalysis,
};
use crate::{download::Downloader, manifests::Url};

/// Analyze an installer from a URL and return installer analysis information.
///
/// When the installer is a ZIP, `matches` can be used to select nested installer
/// files. Plain strings are matched as case-insensitive substrings, while values
/// containing glob metacharacters are matched as glob patterns.
///
/// # Errors
///
/// Returns `InvalidArg` if `url` is invalid.
/// Returns `GenericFailure` if downloading or analyzing the installer fails.
#[napi]
pub async fn analyze_installer(
    url: String,
    matches: Option<Vec<String>>,
) -> napi::Result<AnalyzeInstallerResult> {
    let installer_url = Url::from_str(&url)
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid URL: {e}")))?;

    let downloader = Downloader::new_with_concurrent_and_progress(NonZeroUsize::MIN, false)
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create downloader: {e}"),
            )
        })?;

    let mut downloaded_file = downloader
        .download([installer_url])
        .await
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to download installer: {e}"),
            )
        })?
        .into_iter()
        .next()
        .ok_or_else(|| Error::new(Status::GenericFailure, "No installer was downloaded"))?;

    let mut analyzer =
        crate::analysis::Analyzer::new(&mut downloaded_file.file, &downloaded_file.file_name)
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to analyze installer: {e}"),
                )
            })?;

    if let (Some(zip), Some(matches)) = (&mut analyzer.zip, matches.as_ref())
        && !matches.is_empty()
    {
        analyzer.installers = zip.analyze_matches(matches).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to analyze matching ZIP installers: {e}"),
            )
        })?;
    }

    for installer in &mut analyzer.installers {
        installer.url = downloaded_file.url.inner().clone();
        installer.release_date = downloaded_file.last_modified;
    }

    let analysis = analyzer
        .installers
        .iter()
        .map(|installer| InstallerAnalysis {
            installer_locale: installer
                .locale
                .as_ref()
                .map(std::string::ToString::to_string),
            architecture: installer.architecture.to_string(),
            installer_type: installer.r#type.map(|t| t.to_string()),
            nested_installer_type: installer.nested_installer_type.map(|t| t.to_string()),
            nested_installer_files: installer
                .nested_installer_files
                .iter()
                .map(|f| NestedInstallerFileAnalysis {
                    relative_file_path: f.relative_file_path.to_string(),
                })
                .collect(),
            apps_and_features_entries: installer
                .apps_and_features_entries
                .iter()
                .map(|entry| AppsAndFeaturesEntryAnalysis {
                    display_name: entry.display_name().map(str::to_owned),
                    publisher: entry.publisher().map(str::to_owned),
                    display_version: entry
                        .display_version()
                        .map(std::string::ToString::to_string),
                    product_code: entry.product_code().map(str::to_owned),
                    upgrade_code: entry.upgrade_code().map(str::to_owned),
                    installer_type: entry.installer_type().map(|t| t.to_string()),
                })
                .collect(),
            scope: installer.scope.map(|s| s.to_string()),
            installer_url: installer.url.to_string(),
            installer_sha256: installer.sha_256.to_string(),
            release_date: installer.release_date.map(|d| d.to_string()),
        })
        .collect();

    Ok(AnalyzeInstallerResult {
        analysis,
        file_version: analyzer.file_version,
        product_version: analyzer.product_version,
    })
}
