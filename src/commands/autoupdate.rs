use std::{
    collections::{HashMap, HashSet},
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
};

use camino::Utf8PathBuf;
use clap::Parser;
use color_eyre::eyre::{Result, WrapErr, bail, ensure};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};
use tokio::fs;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use winget_types::{PackageIdentifier, PackageVersion, url::DecodedUrl};

use crate::{
    commands::{strategies::AutoUpdateStrategy, update_version::UpdateVersion},
    github::client::GitHub,
    token::TokenManager,
};

const NO_STRATEGY_CACHE_FILE_PATH: &str = ".komac/autoupdate/no_strategy_cache.json";

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
struct NoStrategyCacheKey {
    package_identifier: String,
}

#[derive(Default, Serialize, Deserialize)]
struct NoStrategyCacheFile {
    entries: Vec<NoStrategyCacheKey>,
}

#[derive(Default)]
struct NoStrategyCache {
    entries: HashSet<NoStrategyCacheKey>,
    is_dirty: bool,
}

impl NoStrategyCache {
    async fn load() -> Result<Self> {
        let path = Utf8PathBuf::from(NO_STRATEGY_CACHE_FILE_PATH);
        let content = match fs::read_to_string(&path).await {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(error)
                    .wrap_err_with(|| format!("Failed to read no-strategy cache at {path}"));
            }
        };

        let parsed = match serde_json::from_str::<NoStrategyCacheFile>(&content) {
            Ok(parsed) => parsed,
            Err(error) => {
                warn!(
                    path = %path,
                    error = %error,
                    "Failed to parse no-strategy cache JSON; ignoring cache file"
                );
                return Ok(Self::default());
            }
        };

        Ok(Self {
            entries: parsed.entries.into_iter().collect(),
            is_dirty: false,
        })
    }

    fn contains(&self, package_identifier: &PackageIdentifier) -> bool {
        self.entries.contains(&NoStrategyCacheKey {
            package_identifier: package_identifier.to_string(),
        })
    }

    fn insert(&mut self, package_identifier: &PackageIdentifier) {
        if self.entries.insert(NoStrategyCacheKey {
            package_identifier: package_identifier.to_string(),
        }) {
            self.is_dirty = true;
        }
    }

    async fn persist_if_dirty(&mut self) -> Result<()> {
        if !self.is_dirty {
            return Ok(());
        }

        let path = Utf8PathBuf::from(NO_STRATEGY_CACHE_FILE_PATH);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .wrap_err_with(|| format!("Failed to create cache directory {parent}"))?;
        }

        let mut entries = self.entries.iter().cloned().collect::<Vec<_>>();
        entries
            .sort_unstable_by(|left, right| left.package_identifier.cmp(&right.package_identifier));

        let serialized = serde_json::to_string_pretty(&NoStrategyCacheFile { entries })
            .wrap_err("Failed to serialize no-strategy cache")?;

        fs::write(&path, format!("{serialized}\n"))
            .await
            .wrap_err_with(|| format!("Failed to write no-strategy cache at {path}"))?;

        self.is_dirty = false;
        Ok(())
    }
}

/// Auto-detect update parameters from an upstream source URL and run update
#[derive(Parser)]
pub struct AutoUpdate {
    /// The package's unique identifier
    package_identifier: Option<PackageIdentifier>,

    /// Source URL used to detect and run an autoupdate strategy (inferred from the winget repo if omitted)
    #[arg(requires = "package_identifier", value_hint = clap::ValueHint::Url)]
    url: Option<DecodedUrl>,

    /// YAML file containing `ID: URL` or `ID: [URL, URL, ...]` entries to process in batch mode
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    recipes: Option<Utf8PathBuf>,

    /// File containing newline-separated package identifier substrings to skip (matches on contains)
    #[arg(long = "exclude-file", value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    exclude_files: Vec<Utf8PathBuf>,

    /// Restrict processing to a single first-letter manifest folder (for example, 'c' -> manifests/c)
    #[arg(long = "letter", alias = "start-with", value_name = "LETTER")]
    letter: Option<char>,

    /// Explicit strategy to use (otherwise auto-detected from URL)
    #[arg(long, value_enum)]
    strategy: Option<AutoUpdateStrategy>,

    /// Header name to compare for the vanity-url strategy
    #[arg(long, requires = "state")]
    header: Option<String>,

    /// Expected previous value for the vanity-url strategy header check
    #[arg(long, requires = "header")]
    state: Option<String>,

    /// Number of installers to download at the same time
    #[arg(long, default_value_t = NonZeroUsize::new(num_cpus::get()).unwrap())]
    concurrent_downloads: NonZeroUsize,

    /// List of issues that updating this package would resolve
    #[arg(long)]
    resolves: Vec<NonZeroU32>,

    /// Automatically submit a pull request
    #[arg(short, long)]
    submit: bool,

    /// Name of external tool that invoked Komac
    #[arg(long, env = "KOMAC_CREATED_WITH")]
    created_with: Option<String>,

    /// URL to external tool that invoked Komac
    #[arg(long, env = "KOMAC_CREATED_WITH_URL", value_hint = clap::ValueHint::Url)]
    created_with_url: Option<DecodedUrl>,

    /// Directory to output the manifests to
    #[arg(short, long, env = "OUTPUT_DIRECTORY", value_hint = clap::ValueHint::DirPath)]
    output: Option<camino::Utf8PathBuf>,

    /// Open pull request link automatically
    #[arg(long, env = "OPEN_PR")]
    open_pr: bool,

    /// Run without submitting
    #[arg(long, env = "DRY_RUN")]
    dry_run: bool,

    /// Package version to replace
    #[arg(short, long, num_args = 0..=1, default_missing_value = "latest")]
    replace: Option<PackageVersion>,

    /// Skip checking for existing pull requests
    #[arg(long, env)]
    skip_pr_check: bool,

    /// Stop on the first entry that fails in --recipes mode
    #[arg(long)]
    fail_fast: bool,

    /// GitHub personal access token with the `public_repo` scope
    #[arg(short, long, env = "GITHUB_TOKEN")]
    token: Option<String>,
}

impl AutoUpdate {
    pub async fn run(self) -> Result<()> {
        let excluded_substrings = read_excluded_substrings(&self.exclude_files).await?;

        if !self.exclude_files.is_empty() {
            info!(
                files = self.exclude_files.len(),
                count = excluded_substrings.len(),
                "Loaded package exclusions from files"
            );
        }

        if !excluded_substrings.is_empty() {
            info!(
                count = excluded_substrings.len(),
                "Applying package exclusions (substring match)"
            );
        }

        if let Some(letter) = self.letter {
            info!(
                letter = letter.to_string(),
                "Restricting package scan to this letter"
            );
        }

        let token = TokenManager::handle(self.token.as_deref()).await?;
        let github = GitHub::new(&token)?;
        let no_strategy_cache = Arc::new(Mutex::new(NoStrategyCache::load().await?));

        info!(
            count = no_strategy_cache.lock().await.entries.len(),
            path = NO_STRATEGY_CACHE_FILE_PATH,
            "Loaded no-strategy cache entries"
        );

        if let Some(recipes_file) = self.recipes.as_ref() {
            let mut file_content = fs::read_to_string(recipes_file)
                .await
                .wrap_err_with(|| format!("Failed to read {recipes_file}"))?;
            let recipes = parse_recipes(&file_content)?;
            let total_recipe_entries = recipes.len();
            let recipes = recipes
                .into_iter()
                .filter(|(package_identifier, _)| {
                    !is_package_excluded(package_identifier, &excluded_substrings, self.letter)
                })
                .collect::<Vec<_>>();
            let excluded_recipe_entries = total_recipe_entries.saturating_sub(recipes.len());

            info!(
                file = %recipes_file,
                count = recipes.len(),
                "Processing autoupdate recipes"
            );

            if excluded_recipe_entries > 0 {
                info!(
                    excluded = excluded_recipe_entries,
                    "Skipped excluded recipe entries"
                );
            }

            if recipes.is_empty() {
                info!("No recipe entries left to process after filtering");
                return Ok(());
            }

            let mut succeeded = 0usize;
            let mut failed = 0usize;
            let mut states_updated = 0usize;

            if self.fail_fast {
                for (package_identifier, sources) in recipes {
                    let result = self
                        .run_entry(
                            &github,
                            token.as_ref(),
                            Arc::clone(&no_strategy_cache),
                            package_identifier.clone(),
                            None,
                            sources,
                            None,
                        )
                        .await;

                    match result {
                        Ok(state_updates) => {
                            succeeded += 1;

                            if !state_updates.is_empty() {
                                let updated_content = update_recipe_state_values(
                                    &file_content,
                                    &package_identifier,
                                    &state_updates,
                                )?;

                                if updated_content != file_content {
                                    file_content = updated_content;
                                    states_updated += state_updates.len();
                                }
                            }
                        }
                        Err(error) => {
                            error!(
                                package = %package_identifier,
                                error = %error,
                                "Autoupdate entry failed"
                            );
                            if states_updated > 0 {
                                fs::write(recipes_file, &file_content)
                                    .await
                                    .wrap_err_with(|| format!("Failed to write {recipes_file}"))?;
                                info!(
                                    file = %recipes_file,
                                    states_updated,
                                    "Updated recipe state values"
                                );
                            }
                            return Err(error);
                        }
                    }
                }
            } else {
                let results = stream::iter(recipes.into_iter().map(
                    |(package_identifier, sources)| async {
                        let result = self
                            .run_entry(
                                &github,
                                token.as_ref(),
                                Arc::clone(&no_strategy_cache),
                                package_identifier.clone(),
                                None,
                                sources,
                                None,
                            )
                            .await;
                        (package_identifier, result)
                    },
                ))
                .buffer_unordered(2)
                .collect::<Vec<_>>()
                .await;

                for (package_identifier, result) in results {
                    match result {
                        Ok(state_updates) => {
                            succeeded += 1;

                            if !state_updates.is_empty() {
                                let updated_content = update_recipe_state_values(
                                    &file_content,
                                    &package_identifier,
                                    &state_updates,
                                )?;

                                if updated_content != file_content {
                                    file_content = updated_content;
                                    states_updated += state_updates.len();
                                }
                            }
                        }
                        Err(error) => {
                            failed += 1;
                            error!(
                                package = %package_identifier,
                                error = %error,
                                "Autoupdate entry failed"
                            );
                        }
                    }
                }
            }

            if states_updated > 0 {
                fs::write(recipes_file, &file_content)
                    .await
                    .wrap_err_with(|| format!("Failed to write {recipes_file}"))?;
                info!(file = %recipes_file, states_updated, "Updated recipe state values");
            }

            info!(succeeded, failed, "Autoupdate recipes summary");

            if failed > 0 {
                bail!("{failed} auto-update entries failed");
            }

            return Ok(());
        }

        if let Some(package_identifier) = self.package_identifier.clone() {
            if is_package_excluded(&package_identifier, &excluded_substrings, self.letter) {
                info!(
                    package = %package_identifier,
                    "Package excluded from auto-update; skipping"
                );
                return Ok(());
            }

            let (latest_version, sources) = if let Some(url) = self.url.clone() {
                (
                    None,
                    vec![RecipeSource {
                        url: Some(url),
                        page: None,
                        header: self.header.clone(),
                        value: self.state.clone(),
                    }],
                )
            } else {
                let (latest_version, sources) =
                    sources_from_manifest(&github, &package_identifier).await?;
                (Some(latest_version), sources)
            };

            return self
                .run_entry(
                    &github,
                    token.as_ref(),
                    Arc::clone(&no_strategy_cache),
                    package_identifier,
                    latest_version,
                    sources,
                    self.strategy,
                )
                .await
                .map(|_| ());
        }

        info!(
            letter = self.letter.map(|char| char.to_string()),
            "Enumerating package identifiers from winget-pkgs"
        );

        let package_identifiers = github
            .get_package_identifiers_for_letter(self.letter)
            .await?;

        info!(
            count = package_identifiers.len(),
            "Finished enumerating package identifiers"
        );

        let total_packages = package_identifiers.len();
        let package_identifiers = package_identifiers
            .into_iter()
            .filter(|package_identifier| {
                !is_package_excluded(package_identifier, &excluded_substrings, self.letter)
            })
            .collect::<Vec<_>>();
        let excluded_count = total_packages.saturating_sub(package_identifiers.len());

        info!(
            count = package_identifiers.len(),
            "No package identifier provided — processing all packages from winget-pkgs"
        );

        if excluded_count > 0 {
            info!(excluded = excluded_count, "Skipped excluded packages");
        }

        if package_identifiers.is_empty() {
            info!("No packages left to process after filtering");
            return Ok(());
        }

        if self.fail_fast {
            for package_identifier in package_identifiers {
                if no_strategy_cache.lock().await.contains(&package_identifier) {
                    info!(
                        package = %package_identifier,
                        "Skipping package because no-strategy cache entry exists"
                    );
                    continue;
                }

                let latest_version =
                    latest_version_from_manifest(&github, &package_identifier).await?;

                let sources = sources_from_manifest_for_version(
                    &github,
                    &package_identifier,
                    &latest_version,
                )
                .await?;
                self.run_entry(
                    &github,
                    token.as_ref(),
                    Arc::clone(&no_strategy_cache),
                    package_identifier,
                    Some(latest_version),
                    sources,
                    self.strategy,
                )
                .await?;
            }
            return Ok(());
        }

        let results = stream::iter(package_identifiers.into_iter().map(
            |package_identifier| async {
                let result = if no_strategy_cache.lock().await.contains(&package_identifier) {
                    info!(
                        package = %package_identifier,
                        "Skipping package because no-strategy cache entry exists"
                    );
                    Ok(Vec::new())
                } else {
                    let latest_version =
                        latest_version_from_manifest(&github, &package_identifier).await;
                    match latest_version {
                        Ok(latest_version) => {
                            let sources = sources_from_manifest_for_version(
                                &github,
                                &package_identifier,
                                &latest_version,
                            )
                            .await;

                            match sources {
                                Ok(sources) => {
                                    self.run_entry(
                                        &github,
                                        token.as_ref(),
                                        Arc::clone(&no_strategy_cache),
                                        package_identifier.clone(),
                                        Some(latest_version),
                                        sources,
                                        self.strategy,
                                    )
                                    .await
                                }
                                Err(error) => Err(error),
                            }
                        }
                        Err(error) => Err(error),
                    }
                };

                (package_identifier, result)
            },
        ))
        .buffer_unordered(2)
        .collect::<Vec<_>>()
        .await;

        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for (package_identifier, result) in results {
            match result {
                Ok(_) => succeeded += 1,
                Err(error) => {
                    failed += 1;
                    error!(
                        package = %package_identifier,
                        error = %error,
                        "Autoupdate entry failed"
                    );
                }
            }
        }

        info!(succeeded, failed, "Autoupdate all-packages summary");

        if failed > 0 {
            bail!("{failed} auto-update entries failed");
        }

        Ok(())
    }

    async fn run_entry(
        &self,
        github: &GitHub,
        token: &str,
        no_strategy_cache: Arc<Mutex<NoStrategyCache>>,
        package_identifier: PackageIdentifier,
        latest_version: Option<PackageVersion>,
        sources: Vec<RecipeSource>,
        strategy_override: Option<AutoUpdateStrategy>,
    ) -> Result<Vec<RecipeStateUpdate>> {
        ensure!(
            !sources.is_empty(),
            "No source URLs were provided for {package_identifier}"
        );

        if no_strategy_cache.lock().await.contains(&package_identifier) {
            info!(
                package = %package_identifier,
                "Skipping package because no-strategy cache entry exists"
            );
            return Ok(Vec::new());
        }

        let latest_version = if let Some(version) = latest_version {
            version
        } else {
            let versions = github.get_versions(&package_identifier).await?;
            versions.last().cloned().unwrap_or_else(|| unreachable!())
        };

        let mut package_version = None;
        let mut resolved_urls = Vec::new();
        let mut release_notes_url = None;
        let mut should_update = false;
        let mut skip_version_check = true;
        let mut state_updates = Vec::new();

        for source in sources {
            let strategy_result = if let Some(page_url) = &source.page {
                crate::commands::strategies::html_page::resolve(&latest_version, page_url).await?
            } else {
                let source_url = source.url.as_ref().unwrap_or_else(|| unreachable!());
                let effective_header = source.header.as_deref().or(self.header.as_deref());
                let effective_value = source.value.as_deref().or(self.state.as_deref());

                ensure!(
                    effective_header.is_some() == effective_value.is_some(),
                    "Recipe source for {package_identifier} must provide both header and value"
                );

                let result = AutoUpdateStrategy::resolve(
                    github,
                    &package_identifier,
                    &latest_version,
                    source_url,
                    strategy_override.or(self.strategy),
                    effective_header,
                    effective_value,
                )
                .await;

                let result = match result {
                    Ok(result) => result,
                    Err(error) => {
                        let error_msg = error.to_string();
                        if error_msg.contains("No autoupdate strategy matched") {
                            let mut cache = no_strategy_cache.lock().await;
                            cache.insert(&package_identifier);
                            cache.persist_if_dirty().await?;

                            tracing::warn!(
                                package = %package_identifier,
                                latest_version = %latest_version,
                                url = %source_url,
                                "No autoupdate strategy matched; cached and skipping"
                            );
                            return Ok(Vec::new());
                        }

                        tracing::error!(
                            package = %package_identifier,
                            url = %source_url,
                            error = %error,
                            "Strategy resolution failed"
                        );

                        // Keep troubleshooting hints at debug level so normal info output stays concise.
                        if error_msg.contains("No suitable release found") {
                            tracing::debug!(
                                package = %package_identifier,
                                url = %source_url,
                                "Hint: release tags may not be parseable semver; consider vanity_url/html_page strategy or channel-specific package"
                            );
                        } else if error_msg.contains("HTTP status client error (404") {
                            tracing::debug!(
                                package = %package_identifier,
                                url = %source_url,
                                "Hint: verify owner/repo path or use a non-github_releases strategy"
                            );
                        } else if error_msg.contains("Not a github-releases URL") {
                            tracing::debug!(
                                package = %package_identifier,
                                url = %source_url,
                                "Hint: expected github_releases source format is https://github.com/OWNER/REPO"
                            );
                        }

                        return Err(error);
                    }
                };

                if effective_header.is_some()
                    && let Some(observed_state) = result.observed_state.clone()
                {
                    state_updates.push(RecipeStateUpdate {
                        url: source_url.clone(),
                        value: observed_state,
                    });
                }

                result
            };

            if let Some(existing_version) = package_version.as_ref() {
                ensure!(
                    existing_version == &strategy_result.package_version,
                    "Resolved URLs for {package_identifier} produced different versions: {} and {}",
                    existing_version,
                    strategy_result.package_version
                );
            } else {
                package_version = Some(strategy_result.package_version.clone());
            }

            if release_notes_url.is_none() {
                release_notes_url = strategy_result.release_notes_url.clone();
            }

            should_update |= strategy_result.should_update;
            skip_version_check &= strategy_result.skip_version_check;

            for resolved_url in strategy_result.urls {
                if !resolved_urls.contains(&resolved_url) {
                    resolved_urls.push(resolved_url);
                }
            }
        }

        let package_version = package_version.unwrap_or_else(|| unreachable!());

        if !should_update {
            info!(
                package = %package_identifier,
                urls = %resolved_urls.len(),
                "No update required"
            );
            return Ok(Vec::new());
        }

        if !skip_version_check && package_version <= latest_version {
            info!(
                package = %package_identifier,
                latest_version = %latest_version,
                source_version = %package_version,
                "Source version is not newer; skipping download and submission"
            );
            return Ok(Vec::new());
        }

        let update_package_version = if skip_version_check {
            None
        } else {
            Some(package_version)
        };

        // Sort URLs: non-zip files alphabetically, then zip files alphabetically
        let (mut non_zip_urls, mut zip_urls): (Vec<_>, Vec<_>) = resolved_urls
            .into_iter()
            .partition(|url| !url.as_str().ends_with(".zip"));

        non_zip_urls.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        zip_urls.sort_by(|a, b| a.as_str().cmp(b.as_str()));

        non_zip_urls.extend(zip_urls);
        let sorted_urls = non_zip_urls;

        UpdateVersion {
            package_identifier,
            package_version: update_package_version,
            urls: sorted_urls,
            files: Vec::new(),
            concurrent_downloads: self.concurrent_downloads,
            resolves: self.resolves.clone(),
            submit: self.submit,
            release_notes_url,
            created_with: self.created_with.clone(),
            created_with_url: self.created_with_url.clone(),
            output: self.output.clone(),
            open_pr: self.open_pr,
            dry_run: self.dry_run,
            replace: self.replace.clone(),
            skip_pr_check: self.skip_pr_check,
            token: Some(token.to_owned()),
        }
        .run()
        .await?;

        Ok(state_updates)
    }
}

fn is_package_excluded(
    package_identifier: &PackageIdentifier,
    excluded_substrings: &[String],
    letter: Option<char>,
) -> bool {
    let id_str = package_identifier.as_str();
    let id_lower = id_str.to_lowercase();

    // Restrict processing to a single first-letter bucket when requested.
    if let Some(letter) = letter {
        let first_char = id_lower.chars().next().unwrap_or('a');
        if first_char != letter.to_lowercase().next().unwrap_or('a') {
            return true;
        }
    }

    // Check if matches any excluded substring
    excluded_substrings
        .iter()
        .any(|substring| id_lower.contains(&substring.to_lowercase()))
}

async fn read_excluded_substrings(files: &[Utf8PathBuf]) -> Result<Vec<String>> {
    let mut excluded_substrings = Vec::new();

    for file in files {
        let file_content = fs::read_to_string(file)
            .await
            .wrap_err_with(|| format!("Failed to read exclusion file {file}"))?;

        let parsed = parse_excluded_substrings(&file_content)
            .wrap_err_with(|| format!("Failed to parse exclusion file {file}"))?;

        excluded_substrings.extend(parsed);
    }

    Ok(excluded_substrings)
}

fn parse_excluded_substrings(file_content: &str) -> Result<Vec<String>> {
    let mut excluded_substrings = Vec::new();

    for line in file_content.lines() {
        let trimmed_line = line.trim();

        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }

        excluded_substrings.push(trimmed_line.to_string());
    }

    Ok(excluded_substrings)
}

#[derive(Debug, Clone)]
struct RecipeStateUpdate {
    url: DecodedUrl,
    value: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RecipeSource {
    url: Option<DecodedUrl>,
    page: Option<DecodedUrl>,
    header: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_scalar_string")]
    value: Option<String>,
}

fn deserialize_optional_scalar_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_yaml::Value>::deserialize(deserializer)?;

    match value {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(text)) => Ok(Some(text)),
        Some(serde_yaml::Value::Number(number)) => Ok(Some(number.to_string())),
        Some(serde_yaml::Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(_) => Err(D::Error::custom(
            "value must be a scalar (string/number/bool)",
        )),
    }
}

impl RecipeSource {
    fn from_url(url: DecodedUrl) -> Self {
        Self {
            url: Some(url),
            page: None,
            header: None,
            value: None,
        }
    }
}

/// Fetch the latest installer manifest from the winget-pkgs repository and
/// build [`RecipeSource`] entries from the unique installer URLs it contains.
async fn sources_from_manifest(
    github: &GitHub,
    package_identifier: &PackageIdentifier,
) -> Result<(PackageVersion, Vec<RecipeSource>)> {
    let latest_version = latest_version_from_manifest(github, package_identifier).await?;
    let sources =
        sources_from_manifest_for_version(github, package_identifier, &latest_version).await?;
    Ok((latest_version, sources))
}

async fn latest_version_from_manifest(
    github: &GitHub,
    package_identifier: &PackageIdentifier,
) -> Result<PackageVersion> {
    let versions = github.get_versions(package_identifier).await?;
    Ok(versions.last().cloned().unwrap_or_else(|| unreachable!()))
}

async fn sources_from_manifest_for_version(
    github: &GitHub,
    package_identifier: &PackageIdentifier,
    latest_version: &PackageVersion,
) -> Result<Vec<RecipeSource>> {
    let manifests = github
        .get_manifests(package_identifier, latest_version)
        .await?;

    let mut seen = HashSet::new();
    let sources: Vec<RecipeSource> = manifests
        .installer
        .installers
        .iter()
        .filter(|installer| seen.insert(installer.url.as_str().to_owned()))
        .map(|installer| RecipeSource::from_url(installer.url.clone()))
        .collect();

    ensure!(
        !sources.is_empty(),
        "Installer manifest for {package_identifier} {latest_version} contains no installer URLs"
    );

    Ok(sources)
}

fn parse_recipes(file_content: &str) -> Result<Vec<(PackageIdentifier, Vec<RecipeSource>)>> {
    let root = serde_yaml::from_str::<serde_yaml::Value>(file_content)
        .wrap_err("Failed to parse recipes YAML")?;
    let mapping = root
        .as_mapping()
        .ok_or_else(|| color_eyre::eyre::eyre!("Recipes YAML root must be a mapping"))?;

    mapping
        .iter()
        .map(|(package_identifier, value)| {
            let package_identifier = package_identifier.as_str().ok_or_else(|| {
                color_eyre::eyre::eyre!("Recipe package identifier keys must be strings")
            })?;

            let urls = parse_recipe_sources(value.clone())
                .wrap_err_with(|| format!("Invalid recipe entry for {package_identifier}"))?;
            ensure!(
                !urls.is_empty(),
                "Recipe entry has no URLs: {package_identifier}"
            );

            for source in &urls {
                ensure!(
                    source.url.is_some() != source.page.is_some(),
                    "Recipe source for {package_identifier} must have exactly one of 'url' or 'page'"
                );
                ensure!(
                    source.header.is_some() == source.value.is_some(),
                    "Recipe source for {package_identifier} must include both header and value"
                );
            }

            package_identifier
                .parse::<PackageIdentifier>()
                .map(|identifier| (identifier, urls))
                .wrap_err_with(|| format!("Invalid package identifier: {package_identifier}"))
        })
        .collect()
}

fn parse_recipe_sources(value: serde_yaml::Value) -> Result<Vec<RecipeSource>> {
    match value {
        serde_yaml::Value::String(url) => {
            let url = url.parse::<DecodedUrl>().wrap_err("Invalid recipe URL")?;
            Ok(vec![RecipeSource::from_url(url)])
        }
        serde_yaml::Value::Mapping(_) => {
            let source = serde_yaml::from_value::<RecipeSource>(value)
                .wrap_err("Invalid structured recipe source")?;
            Ok(vec![source])
        }
        serde_yaml::Value::Sequence(values) => values
            .into_iter()
            .map(|item| match item {
                serde_yaml::Value::String(url) => url
                    .parse::<DecodedUrl>()
                    .map(RecipeSource::from_url)
                    .wrap_err("Invalid recipe URL"),
                serde_yaml::Value::Mapping(_) => serde_yaml::from_value::<RecipeSource>(item)
                    .wrap_err("Invalid structured recipe source"),
                _ => bail!("Recipe list items must be URL strings or source objects"),
            })
            .collect(),
        _ => bail!("Recipe entry must be a URL string, source object, or list"),
    }
}

fn update_recipe_state_values(
    file_content: &str,
    package_identifier: &PackageIdentifier,
    state_updates: &[RecipeStateUpdate],
) -> Result<String> {
    if state_updates.is_empty() {
        return Ok(file_content.to_owned());
    }

    let updates = state_updates
        .iter()
        .map(|update| (update.url.as_str().to_owned(), update.value.clone()))
        .collect::<HashMap<_, _>>();

    let mut lines = file_content.lines().map(str::to_owned).collect::<Vec<_>>();

    let package_header = format!("{package_identifier}:");
    let Some(section_start) = lines.iter().position(|line| line.trim() == package_header) else {
        return Ok(file_content.to_owned());
    };

    let section_end = lines
        .iter()
        .enumerate()
        .skip(section_start + 1)
        .find_map(|(index, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || line.starts_with(' ') {
                None
            } else {
                Some(index)
            }
        })
        .unwrap_or(lines.len());

    let item_starts = (section_start + 1..section_end)
        .filter(|index| lines[*index].trim_start().starts_with("- url:"))
        .collect::<Vec<_>>();

    for item_index in (0..item_starts.len()).rev() {
        let start = item_starts[item_index];
        let end = if item_index + 1 < item_starts.len() {
            item_starts[item_index + 1]
        } else {
            section_end
        };

        let url = lines[start]
            .trim_start()
            .trim_start_matches("- url:")
            .trim()
            .trim_matches(['"', '\'']);

        let Some(new_value) = updates.get(url) else {
            continue;
        };

        let item_indent = lines[start]
            .chars()
            .take_while(|character| character.is_whitespace())
            .collect::<String>();
        let field_indent = format!("{item_indent}  ");
        let rendered_value = format!(
            "{}value: \"{}\"",
            field_indent,
            escape_yaml_string(new_value)
        );

        if let Some(value_index) =
            (start + 1..end).find(|index| lines[*index].trim_start().starts_with("value:"))
        {
            lines[value_index] = rendered_value;
            continue;
        }

        let insert_index = (start + 1..end)
            .find(|index| lines[*index].trim_start().starts_with("header:"))
            .map_or(start + 1, |header_index| header_index + 1);

        lines.insert(insert_index, rendered_value);
    }

    Ok(format!("{}\n", lines.join("\n")))
}

fn escape_yaml_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::{
        RecipeStateUpdate, escape_yaml_string, parse_excluded_substrings, parse_recipes,
        update_recipe_state_values,
    };
    use winget_types::{PackageIdentifier, url::DecodedUrl};

    #[test]
    fn parses_yaml_mapping_with_comments() {
        let yaml = r#"
# comment
Example.Package: https://sourceforge.net/projects/example/
Another.Package: https://example.com/installer.exe
"#;

        let recipes = parse_recipes(yaml).unwrap();
        assert_eq!(recipes.len(), 2);
        assert_eq!(recipes[0].0.as_str(), "Example.Package");
        assert_eq!(recipes[0].1.len(), 1);
        assert_eq!(recipes[1].0.as_str(), "Another.Package");
        assert_eq!(recipes[1].1.len(), 1);
    }

    #[test]
    fn parses_yaml_mapping_with_url_list() {
        let yaml = r#"
Example.Package:
  - https://example.com/installer-x64.exe
  - https://example.com/installer-arm64.exe
"#;

        let recipes = parse_recipes(yaml).unwrap();
        assert_eq!(recipes.len(), 1);
        assert_eq!(recipes[0].0.as_str(), "Example.Package");
        assert_eq!(recipes[0].1.len(), 2);
    }

    #[test]
    fn parses_yaml_mapping_with_structured_sources() {
        let yaml = r#"
Example.Package:
  - url: https://example.com/installer-x64.exe
    header: Content-Length
    value: 123
  - url: https://example.com/installer-arm64.exe
    header: Content-Length
    value: 123
"#;

        let recipes = parse_recipes(yaml).unwrap();
        assert_eq!(recipes.len(), 1);
        assert_eq!(recipes[0].0.as_str(), "Example.Package");
        assert_eq!(recipes[0].1.len(), 2);
        assert_eq!(recipes[0].1[0].value.as_deref(), Some("123"));
    }

    #[test]
    fn updates_recipe_state_values_for_structured_sources() {
        let yaml = r#"
Microsoft.GlobalSecureAccessClient:
  - url: https://aka.ms/GlobalSecureAccess-windows
    header: Content-Length
    value: "0"
  - url: https://aka.ms/GlobalSecureAccess-WindowsOnArm
    header: Content-Length
    value: "0"
"#;

        let updates = vec![
            RecipeStateUpdate {
                url: "https://aka.ms/GlobalSecureAccess-windows"
                    .parse::<DecodedUrl>()
                    .unwrap(),
                value: "149218760".to_string(),
            },
            RecipeStateUpdate {
                url: "https://aka.ms/GlobalSecureAccess-WindowsOnArm"
                    .parse::<DecodedUrl>()
                    .unwrap(),
                value: "155425944".to_string(),
            },
        ];
        let package_identifier = "Microsoft.GlobalSecureAccessClient"
            .parse::<PackageIdentifier>()
            .unwrap();

        let updated = update_recipe_state_values(yaml, &package_identifier, &updates).unwrap();

        assert!(updated.contains("value: \"149218760\""));
        assert!(updated.contains("value: \"155425944\""));
    }

    #[test]
    fn escapes_yaml_state_values() {
        assert_eq!(escape_yaml_string("\"abc\""), "\\\"abc\\\"");
    }

    #[test]
    fn parses_excluded_substrings_from_lines() {
        let content = r#"
# comment
Example.Package

Another.Package
"#;

        let excluded = parse_excluded_substrings(content).unwrap();

        assert_eq!(excluded.len(), 2);
        assert!(excluded.iter().any(|s| s == "Example.Package"));
        assert!(excluded.iter().any(|s| s == "Another.Package"));
    }

    #[test]
    fn parses_excluded_substrings_for_substring_match() {
        let content = r#"
beta
alpha.rc
"#;

        let excluded = parse_excluded_substrings(content).unwrap();

        assert_eq!(excluded.len(), 2);
        assert!(excluded.iter().any(|s| s == "beta"));
        assert!(excluded.iter().any(|s| s == "alpha.rc"));
    }
}
