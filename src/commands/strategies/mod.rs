pub mod github_releases;
pub mod html_page;
pub mod sourceforge;
pub mod vanity_url;

use clap::ValueEnum;
use color_eyre::eyre::Result;
use winget_types::{
    PackageIdentifier, PackageVersion,
    url::{DecodedUrl, ReleaseNotesUrl},
};

use crate::{github::client::GitHub, manifests::Url};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateVersionStrategyResult {
    pub package_version: PackageVersion,
    pub urls: Vec<Url>,
    pub release_notes_url: Option<ReleaseNotesUrl>,
    pub observed_state: Option<String>,
    pub should_update: bool,
    pub skip_version_check: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AutoUpdateStrategy {
    GithubReleases,
    SourceForge,
    VanityUrl,
}

impl AutoUpdateStrategy {
    const AUTO_STRATEGIES: [Self; 2] = [Self::GithubReleases, Self::SourceForge];

    pub async fn resolve(
        github: &GitHub,
        package_identifier: &PackageIdentifier,
        latest_version: &PackageVersion,
        source_url: &DecodedUrl,
        strategy: Option<Self>,
        header: Option<&str>,
        state: Option<&str>,
    ) -> Result<UpdateVersionStrategyResult> {
        if let Some(strategy) = strategy {
            return Self::resolve_with(
                strategy,
                github,
                package_identifier,
                latest_version,
                source_url,
                header,
                state,
            )
            .await
            .map_err(Into::into);
        }

        for strategy in Self::AUTO_STRATEGIES {
            match Self::resolve_with(
                strategy,
                github,
                package_identifier,
                latest_version,
                source_url,
                header,
                state,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(StrategyResolveError::GithubReleases(
                    github_releases::GithubReleasesError::NotGithubReleasesUrl,
                )) => {}
                Err(StrategyResolveError::SourceForge(
                    sourceforge::SourceForgeError::NotSourceForgeProjectUrl,
                )) => {}
                Err(error) => return Err(error.into()),
            }
        }

        Err(StrategyResolveError::NoStrategyMatched(source_url.to_string()).into())
    }

    async fn resolve_with(
        strategy: Self,
        github: &GitHub,
        package_identifier: &PackageIdentifier,
        latest_version: &PackageVersion,
        source_url: &DecodedUrl,
        header: Option<&str>,
        state: Option<&str>,
    ) -> Result<UpdateVersionStrategyResult, StrategyResolveError> {
        match strategy {
            Self::GithubReleases => {
                github_releases::resolve(github, package_identifier, source_url)
                    .await
                    .map_err(StrategyResolveError::GithubReleases)
            }
            Self::SourceForge => {
                sourceforge::resolve(github, package_identifier, latest_version, source_url)
                    .await
                    .map_err(StrategyResolveError::SourceForge)
            }
            Self::VanityUrl => vanity_url::resolve(
                github,
                package_identifier,
                latest_version,
                source_url,
                header,
                state,
            )
            .await
            .map_err(StrategyResolveError::VanityUrl),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum StrategyResolveError {
    #[error(transparent)]
    GithubReleases(#[from] github_releases::GithubReleasesError),
    #[error(transparent)]
    SourceForge(#[from] sourceforge::SourceForgeError),
    #[error(transparent)]
    VanityUrl(#[from] vanity_url::VanityUrlError),
    #[error("No autoupdate strategy matched URL: {0}")]
    NoStrategyMatched(String),
}
