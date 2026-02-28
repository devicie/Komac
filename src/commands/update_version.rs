use std::{
    collections::BTreeSet,
    collections::HashMap,
    collections::HashSet,
    io::{Read, Seek},
    mem,
    num::{NonZeroU32, NonZeroUsize},
};

use anstream::println;
use camino::Utf8PathBuf;
use clap::Parser;
use color_eyre::eyre::{Error, Result, bail, ensure};
use futures_util::TryFutureExt;
use indicatif::ProgressBar;
use itertools::Itertools;
use owo_colors::OwoColorize;
use strsim::levenshtein;
use tokio::try_join;
use winget_types::{
    PackageIdentifier, PackageVersion,
    installer::{InstallerType, MinimumOSVersion, NestedInstallerFiles},
    url::{DecodedUrl, ReleaseNotesUrl},
};

use crate::{
    analysis::{Analyzer, installers::Zip},
    commands::utils::{
        SPINNER_TICK_RATE, SubmitOption, prompt_existing_pull_request, write_changes_to_dir,
    },
    download::Downloader,
    download_file::process_files,
    github::{
        GITHUB_HOST, GitHubError, WINGET_PKGS_FULL_NAME,
        client::{GitHub, GitHubValues},
        utils::{PackagePath, pull_request::pr_changes},
    },
    manifests::Url,
    match_installers::match_installers,
    token::TokenManager,
    traits::{LocaleExt, path::NormalizePath},
};

/// Add a version to a pre-existing package
#[expect(clippy::struct_excessive_bools)]
#[derive(Parser)]
pub struct UpdateVersion {
    /// The package's unique identifier
    #[arg()]
    pub(super) package_identifier: PackageIdentifier,

    /// The package's version. If omitted, inferred from PE ProductVersion
    #[arg(short = 'v', long = "version")]
    pub(super) package_version: Option<PackageVersion>,

    /// The list of package installers
    #[arg(short, long, num_args = 1.., required = true, value_hint = clap::ValueHint::Url)]
    pub(super) urls: Vec<Url>,

    /// The list of files to use instead of downloading urls
    #[arg(short, long, num_args = 1.., requires = "urls", value_parser = super::analyze::is_valid_file, value_hint = clap::ValueHint::FilePath)]
    pub(super) files: Vec<Utf8PathBuf>,

    /// Number of installers to download at the same time
    #[arg(long, default_value_t = NonZeroUsize::new(num_cpus::get()).unwrap())]
    pub(super) concurrent_downloads: NonZeroUsize,

    /// List of issues that updating this package would resolve
    #[arg(long)]
    pub(super) resolves: Vec<NonZeroU32>,

    /// Automatically submit a pull request
    #[arg(short, long)]
    pub(super) submit: bool,

    /// URL to package's release notes
    #[arg(long, value_hint = clap::ValueHint::Url)]
    pub(super) release_notes_url: Option<ReleaseNotesUrl>,

    /// Name of external tool that invoked Komac
    #[arg(long, env = "KOMAC_CREATED_WITH")]
    pub(super) created_with: Option<String>,

    /// URL to external tool that invoked Komac
    #[arg(long, env = "KOMAC_CREATED_WITH_URL", value_hint = clap::ValueHint::Url)]
    pub(super) created_with_url: Option<DecodedUrl>,

    /// Directory to output the manifests to
    #[arg(short, long, env = "OUTPUT_DIRECTORY", value_hint = clap::ValueHint::DirPath)]
    pub(super) output: Option<Utf8PathBuf>,

    /// Open pull request link automatically
    #[arg(long, env = "OPEN_PR")]
    pub(super) open_pr: bool,

    /// Run without submitting
    #[arg(long, env = "DRY_RUN")]
    pub(super) dry_run: bool,

    /// Package version to replace
    #[arg(short, long, num_args = 0..=1, default_missing_value = "latest")]
    pub(super) replace: Option<PackageVersion>,

    /// Skip checking for existing pull requests
    #[arg(long, env)]
    pub(super) skip_pr_check: bool,

    /// GitHub personal access token with the `public_repo` scope
    #[arg(short, long, env = "GITHUB_TOKEN")]
    pub(super) token: Option<String>,
}

impl UpdateVersion {
    pub async fn run(mut self) -> Result<()> {
        if !self.files.is_empty() {
            ensure!(
                self.urls.len() == self.files.len(),
                "Number of URLs ({}) must match number of files ({})",
                self.urls.len(),
                self.files.len()
            );
        }

        let token = TokenManager::handle(self.token.as_deref()).await?;
        let github = GitHub::new(&token)?;

        let versions = github.get_versions(&self.package_identifier).await?;

        let latest_version = versions.last().unwrap_or_else(|| unreachable!());
        println!(
            "Latest version of {}: {latest_version}",
            self.package_identifier
        );

        let mut has_checked_existing_pr = false;
        if let Some(package_version) = self.package_version.as_ref() {
            if self
                .should_abort_for_existing_pr(&github, package_version)
                .await?
            {
                return Ok(());
            }
            has_checked_existing_pr = true;
        }

        let downloader = Downloader::new_with_concurrent(self.concurrent_downloads)?;
        let (mut manifests, mut github_values, mut files) = try_join!(
            github
                .get_manifests(&self.package_identifier, latest_version)
                .map_err(Error::new),
            self.fetch_github_values(&github).map_err(Error::new),
            downloader.download(self.urls.iter().cloned()),
        )?;

        let mut download_results = process_files(&mut files).await?;
        if self.package_version.is_none() {
            self.package_version = Some(self.infer_package_version(&download_results)?);
        }
        let package_version = self
            .package_version
            .as_ref()
            .unwrap_or_else(|| unreachable!());

        if !has_checked_existing_pr
            && self
                .should_abort_for_existing_pr(&github, package_version)
                .await?
        {
            return Ok(());
        }

        let replace_version =
            self.resolve_replace_version(&versions, latest_version, package_version)?;

        let installer_results = download_results
            .iter_mut()
            .flat_map(|(_url, analyzer)| mem::take(&mut analyzer.installers))
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

        let duplicate_urls = previous_installers
            .iter()
            .map(|installer| installer.url.clone())
            .duplicates()
            .collect::<Vec<_>>();

        manifests.default_locale.package_version = self.package_version.as_ref().unwrap().clone();
        let matched_installers = match_installers(previous_installers, &installer_results);
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

        let matched_urls = installers
            .iter()
            .map(|installer| installer.url.clone())
            .collect::<HashSet<_>>();

        installers.extend(
            installer_results
                .into_iter()
                .filter(|installer| !matched_urls.contains(&installer.url)),
        );

        manifests.installer.package_version = package_version.clone();
        manifests.installer.minimum_os_version = manifests
            .installer
            .minimum_os_version
            .filter(|minimum_os_version| *minimum_os_version != MinimumOSVersion::new(10, 0, 0, 0));
        manifests.installer.installers = installers;
        manifests.installer.optimize();

        manifests.default_locale.update(
            package_version,
            &mut github_values,
            self.release_notes_url.as_ref(),
        );

        manifests.locales.iter_mut().for_each(|locale| {
            locale.update(
                package_version,
                &mut github_values,
                self.release_notes_url.as_ref(),
            );
        });

        manifests.version.update(package_version);

        let package_path = PackagePath::new(&self.package_identifier, Some(package_version), None);
        let mut changes = pr_changes()
            .package_identifier(&self.package_identifier)
            .manifests(&manifests)
            .package_path(&package_path)
            .maybe_created_with(self.created_with.as_deref())
            .create()?;

        let submit_option = SubmitOption::prompt(
            &mut changes,
            &self.package_identifier,
            package_version,
            self.submit,
            self.dry_run,
        )?;

        if let Some(output) = self
            .output
            .as_ref()
            .map(|out| out.join(package_path.as_str()))
        {
            write_changes_to_dir(&changes, output.as_path()).await?;
            println!(
                "{} written all manifest files to {output}",
                "Successfully".green()
            );
        }

        if submit_option.is_exit() {
            return Ok(());
        }

        // Create an indeterminate progress bar to show as a pull request is being created
        let pr_progress = ProgressBar::new_spinner().with_message(format!(
            "Creating a pull request for {} {}",
            self.package_identifier, package_version
        ));
        pr_progress.enable_steady_tick(SPINNER_TICK_RATE);

        let pull_request = github
            .add_version()
            .identifier(&self.package_identifier)
            .version(package_version)
            .versions(&versions)
            .changes(changes)
            .maybe_replace_version(replace_version)
            .issue_resolves(&self.resolves)
            .maybe_created_with(self.created_with.as_deref())
            .maybe_created_with_url(self.created_with_url.as_ref())
            .send()
            .await?;

        pr_progress.finish_and_clear();

        pull_request.print_success();

        if self.open_pr {
            open::that(pull_request.url().as_str())?;
        }

        Ok(())
    }

    fn resolve_replace_version<'a>(
        &'a self,
        versions: &'a BTreeSet<PackageVersion>,
        latest_version: &'a PackageVersion,
        package_version: &PackageVersion,
    ) -> Result<Option<&'a PackageVersion>> {
        let replace_version = self
            .replace
            .as_ref()
            .map(|version| {
                if version.is_latest() {
                    latest_version
                } else {
                    version
                }
            })
            .filter(|&version| version.as_str() != package_version.as_str());

        if let Some(version) = replace_version
            && !versions.contains(version)
            && let Some(closest) = version.closest(versions)
        {
            bail!(
                "Replacement version {version} does not exist in {WINGET_PKGS_FULL_NAME}. The closest version is {closest}"
            )
        }

        Ok(replace_version)
    }

    async fn should_abort_for_existing_pr(
        &self,
        github: &GitHub,
        package_version: &PackageVersion,
    ) -> Result<bool> {
        if let Some(ref pull_request) = github
            .get_existing_pull_request(&self.package_identifier, package_version)
            .await?
            && !self.skip_pr_check
            && !self.dry_run
            && !prompt_existing_pull_request(
                &self.package_identifier,
                package_version,
                pull_request,
            )?
        {
            return Ok(true);
        }

        Ok(false)
    }

    fn infer_package_version<R: Read + Seek>(
        &self,
        download_results: &HashMap<DecodedUrl, Analyzer<'_, R>>,
    ) -> Result<PackageVersion> {
        let versions = download_results
            .values()
            .filter_map(|analyzer| analyzer.package_version.clone())
            .collect::<BTreeSet<_>>();

        if versions.is_empty() {
            bail!(
                "No --version was provided and no PE ProductVersion metadata was found. Pass --version explicitly."
            );
        }

        if versions.len() > 1 {
            let detected_versions = versions
                .iter()
                .map(PackageVersion::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "No --version was provided and multiple PE ProductVersion values were detected: {detected_versions}. Pass --version explicitly."
            );
        }

        versions.into_iter().next().map_or_else(
            || unreachable!(),
            |package_version| {
                println!("Using PE ProductVersion {package_version} as package version");
                Ok(package_version)
            },
        )
    }

    async fn fetch_github_values(
        &self,
        github: &GitHub,
    ) -> Result<Option<GitHubValues>, GitHubError> {
        if let Some(url) = self
            .urls
            .iter()
            .find(|url| url.host_str() == Some(GITHUB_HOST))
        {
            github
                .get_all_values_from_url(url.clone().into_inner())
                .await
                .transpose()
        } else {
            Ok(None)
        }
    }
}

fn fix_relative_paths<R: Read + Seek>(
    nested_installer_files: BTreeSet<NestedInstallerFiles>,
    zip: Option<&Zip<R>>,
) -> BTreeSet<NestedInstallerFiles> {
    let Some(zip) = zip else {
        return nested_installer_files;
    };

    nested_installer_files
        .into_iter()
        .filter_map(|nested_installer_files| {
            if zip
                .possible_installer_files
                .contains(&nested_installer_files.relative_file_path.normalize())
            {
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
}
