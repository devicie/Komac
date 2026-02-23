use std::{collections::BTreeSet, mem, num::NonZeroUsize};

use anstream::println;
use clap::Parser;
use color_eyre::eyre::Result;
use indicatif::ProgressBar;
use owo_colors::OwoColorize;
use similar::{ChangeTag, TextDiff};
use strsim::levenshtein;
use winget_types::{
    PackageIdentifier, PackageVersion,
    installer::{InstallerType, MinimumOSVersion, NestedInstallerFiles},
};

use crate::{
    commands::utils::SPINNER_TICK_RATE, download::Downloader, download_file::process_files,
    github::client::GitHub, match_installers::match_installers, token::TokenManager,
    traits::path::NormalizePath,
};

/// Compare Komac's installer analysis against existing winget-pkgs manifests
#[derive(Parser)]
#[clap(visible_alias = "compare")]
pub struct CompareInstallers {
    /// Exact package identifier to compare
    #[arg()]
    package_identifier: PackageIdentifier,

    /// Compare all versions instead of only the latest
    #[arg(long)]
    all_versions: bool,

    /// Minimum version to compare (inclusive)
    #[arg(long)]
    min_version: Option<PackageVersion>,

    /// Maximum version to compare (inclusive)
    #[arg(long)]
    max_version: Option<PackageVersion>,

    /// Number of installers to download at the same time
    #[arg(long, default_value_t = NonZeroUsize::new(2).unwrap())]
    concurrent_downloads: NonZeroUsize,

    /// GitHub personal access token with the `public_repo` scope
    #[arg(short, long, env = "GITHUB_TOKEN")]
    token: Option<String>,
}

impl CompareInstallers {
    pub async fn run(self) -> Result<()> {
        let CompareInstallers {
            package_identifier,
            all_versions,
            min_version,
            max_version,
            concurrent_downloads,
            token,
        } = self;

        let token = TokenManager::handle(token.as_deref()).await?;
        let github = GitHub::new(&token)?;

        let progress = ProgressBar::new_spinner().with_message("Fetching package versions...");
        progress.enable_steady_tick(SPINNER_TICK_RATE);

        let versions = match github.get_versions(&package_identifier).await {
            Ok(v) => v,
            Err(err) => {
                progress.finish_and_clear();
                println!(
                    "{} Failed to get versions for {}: {err}",
                    "⚠".yellow(),
                    package_identifier
                );
                return Ok(());
            }
        };

        progress.finish_and_clear();

        let downloader = Downloader::new_with_concurrent(concurrent_downloads)?;

        let versions_to_compare: Vec<&PackageVersion> =
            match (all_versions, &min_version, &max_version) {
                (true, _, _) => versions.iter().collect(),
                (false, Some(min), Some(max)) => versions.range(min..=max).collect(),
                (false, Some(min), None) => versions.range(min..).collect(),
                (false, None, Some(max)) => versions.range(..=max).collect(),
                (false, None, None) => versions.iter().next_back().into_iter().collect(),
            };
        let total_versions = versions_to_compare.len();
        let mut total_matches = 0u32;
        let mut total_mismatches = 0u32;
        let mut total_errors = 0u32;

        if versions_to_compare.is_empty() {
            println!(
                "{} No versions matched the selected range for {}",
                "⚠".yellow(),
                package_identifier
            );
            return Ok(());
        }

        println!("\n{} ({total_versions})", package_identifier.bold());

        for version in versions_to_compare {
            match Self::compare_version(&github, &downloader, &package_identifier, version).await {
                Ok(None) => {
                    total_matches += 1;
                    println!("  {} {version}", "✓".green());
                }
                Ok(Some(diff)) => {
                    total_mismatches += 1;
                    println!("  {} {version}", "✗".red());
                    for line in diff.lines() {
                        println!("    {line}");
                    }
                }
                Err(err) => {
                    total_errors += 1;
                    println!("  {} {version}: {err}", "⚠".yellow());
                }
            }
        }

        println!("\n{}", "═".repeat(60));
        println!(
            "Packages: {}  Versions: {total_versions}  \
             Matches: {}  Mismatches: {}  Errors: {}",
            1u32,
            total_matches.green(),
            total_mismatches.red(),
            total_errors.yellow()
        );

        Ok(())
    }

    async fn compare_version(
        github: &GitHub,
        downloader: &Downloader,
        identifier: &PackageIdentifier,
        version: &PackageVersion,
    ) -> Result<Option<String>> {
        let mut manifests = github.get_manifests(identifier, version).await?;
        let original_yaml = serde_yaml::to_string(&manifests.installer)?;
        let urls: Vec<_> = manifests
            .installer
            .installers
            .iter()
            .map(|i| i.url.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        if urls.is_empty() {
            return Ok(Some("No installer URLs in manifest".to_owned()));
        }

        let mut files = downloader.download(urls.iter().cloned()).await?;
        let mut download_results = process_files(&mut files).await?;

        let installer_results = download_results
            .iter_mut()
            .flat_map(|(_url, analyser)| mem::take(&mut analyser.installers))
            .collect::<Vec<_>>();

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

        let matched_installers = match_installers(previous_installers, &installer_results);
        let installers = matched_installers
            .into_iter()
            .map(|(previous_installer, new_installer)| {
                let analyser = &download_results[&new_installer.url];
                let installer_type = match previous_installer.r#type {
                    Some(InstallerType::Portable) => previous_installer.r#type,
                    _ => match new_installer.r#type {
                        Some(InstallerType::Portable) => previous_installer.r#type,
                        _ => new_installer.r#type,
                    },
                };

                let previous_nested_files = previous_installer.nested_installer_files.clone();

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
                    installer.nested_installer_files = if let Some(zip) = analyser.zip.as_ref() {
                        nested_files
                            .into_iter()
                            .filter_map(|nested_installer_files| {
                                if zip.possible_installer_files.contains(
                                    &nested_installer_files.relative_file_path.normalize(),
                                ) {
                                    Some(nested_installer_files)
                                } else {
                                    zip.possible_installer_files
                                        .iter()
                                        .min_by_key(|file_path| {
                                            levenshtein(
                                                file_path.as_str(),
                                                nested_installer_files.relative_file_path.as_str(),
                                            )
                                        })
                                        .map(|path| NestedInstallerFiles {
                                            relative_file_path: path.to_path_buf(),
                                            ..nested_installer_files
                                        })
                                }
                            })
                            .collect::<BTreeSet<_>>()
                    } else {
                        nested_files
                    };
                }

                for entry in &mut installer.apps_and_features_entries {
                    entry.deduplicate(&manifests.default_locale);
                }
                installer
            })
            .collect::<Vec<_>>();

        manifests.installer.package_version = version.clone();
        manifests.installer.minimum_os_version = manifests
            .installer
            .minimum_os_version
            .filter(|min_os| *min_os != MinimumOSVersion::new(10, 0, 0, 0));
        manifests.installer.installers = installers;
        manifests.installer.optimize();
        let generated_yaml = serde_yaml::to_string(&manifests.installer)?;

        if original_yaml == generated_yaml {
            Ok(None)
        } else {
            Ok(Some(diff_strings(&original_yaml, &generated_yaml)))
        }
    }
}

fn diff_strings(original: &str, generated: &str) -> String {
    use std::fmt::Write;

    const MAX_OUTPUT_LINES: usize = 120;

    let diff = TextDiff::from_lines(original, generated);
    let mut output = String::new();
    let mut total_changed_lines = 0usize;
    let mut emitted_lines = 0usize;

    for change in diff.iter_all_changes() {
        let (prefix, colorized_line) = match change.tag() {
            ChangeTag::Insert => ("+", change.to_string().trim_end().green().to_string()),
            ChangeTag::Delete => ("-", change.to_string().trim_end().red().to_string()),
            ChangeTag::Equal => continue,
        };

        total_changed_lines += 1;
        if emitted_lines >= MAX_OUTPUT_LINES {
            continue;
        }

        let _ = writeln!(output, "{prefix} {colorized_line}");
        emitted_lines += 1;
    }

    if total_changed_lines > MAX_OUTPUT_LINES {
        let hidden = total_changed_lines - MAX_OUTPUT_LINES;
        let _ = writeln!(output, "{} {hidden} more diff lines", "...".yellow());
    }

    output
}

#[cfg(test)]
mod tests {
    use super::diff_strings;

    #[test]
    fn unified_diff_contains_expected_changes() {
        let original = "a: 1\nb: 2\nc: 3\n";
        let generated = "a: 1\nb: 22\nd: 4\n";
        let diff = diff_strings(original, generated);

        assert!(diff.contains("- "));
        assert!(diff.contains("+ "));
        assert!(diff.contains("b: 2"));
        assert!(diff.contains("b: 22"));
    }
}
