use std::{
    collections::HashMap,
    num::{NonZeroU32, NonZeroUsize},
};

use camino::Utf8PathBuf;
use clap::Parser;
use color_eyre::eyre::{Result, WrapErr, bail, ensure};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Deserializer, de::Error as DeError};
use tokio::fs;
use tracing::{error, info, warn};
use winget_types::{PackageIdentifier, PackageVersion, url::DecodedUrl};

use crate::{
    commands::{strategies::AutoUpdateStrategy, update_version::UpdateVersion},
    github::client::GitHub,
    token::TokenManager,
};

/// Auto-detect update parameters from an upstream source URL and run update
#[derive(Parser)]
pub struct AutoUpdate {
    /// The package's unique identifier
    #[arg(required_unless_present = "recipes", requires = "url")]
    package_identifier: Option<PackageIdentifier>,

    /// Source URL used to detect and run an autoupdate strategy
    #[arg(required_unless_present = "recipes", requires = "package_identifier", value_hint = clap::ValueHint::Url)]
    url: Option<DecodedUrl>,

    /// YAML file containing `ID: URL` or `ID: [URL, URL, ...]` entries to process in batch mode
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    recipes: Option<Utf8PathBuf>,

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
        let token = TokenManager::handle(self.token.as_deref()).await?;
        let github = GitHub::new(&token)?;

        if let Some(recipes_file) = self.recipes.as_ref() {
            let mut file_content = fs::read_to_string(recipes_file)
                .await
                .wrap_err_with(|| format!("Failed to read {recipes_file}"))?;
            let recipes = parse_recipes(&file_content)?;

            info!(
                file = %recipes_file,
                count = recipes.len(),
                "Processing autoupdate recipes"
            );

            let mut succeeded = 0usize;
            let mut failed = 0usize;
            let mut states_updated = 0usize;

            if self.fail_fast {
                for (package_identifier, sources) in recipes {
                    let result = self
                        .run_entry(&github, token.as_ref(), package_identifier.clone(), sources)
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
                            .run_entry(&github, token.as_ref(), package_identifier.clone(), sources)
                            .await;
                        (package_identifier, result)
                    },
                ))
                .buffer_unordered(self.concurrent_downloads.get())
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

        let package_identifier = self
            .package_identifier
            .clone()
            .unwrap_or_else(|| unreachable!());
        let url = self.url.clone().unwrap_or_else(|| unreachable!());

        self.run_entry(
            &github,
            token.as_ref(),
            package_identifier,
            vec![RecipeSource {
                url: Some(url),
                page: None,
                header: self.header.clone(),
                value: self.state.clone(),
            }],
        )
        .await
        .map(|_| ())
    }

    async fn run_entry(
        &self,
        github: &GitHub,
        token: &str,
        package_identifier: PackageIdentifier,
        sources: Vec<RecipeSource>,
    ) -> Result<Vec<RecipeStateUpdate>> {
        ensure!(
            !sources.is_empty(),
            "No source URLs were provided for {package_identifier}"
        );

        let versions = github.get_versions(&package_identifier).await?;
        let latest_version = versions.last().unwrap_or_else(|| unreachable!());

        let mut package_version = None;
        let mut resolved_urls = Vec::new();
        let mut release_notes_url = None;
        let mut should_update = false;
        let mut skip_version_check = true;
        let mut state_updates = Vec::new();

        for source in sources {
            let strategy_result = if let Some(page_url) = &source.page {
                crate::commands::strategies::html_page::resolve(latest_version, page_url).await?
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
                    latest_version,
                    source_url,
                    self.strategy,
                    effective_header,
                    effective_value,
                )
                .await?;

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

        if !skip_version_check && package_version <= *latest_version {
            warn!(
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

        UpdateVersion {
            package_identifier,
            package_version: update_package_version,
            urls: resolved_urls,
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
    use super::{RecipeStateUpdate, escape_yaml_string, parse_recipes, update_recipe_state_values};
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
}
