use camino::Utf8Path;
use color_eyre::eyre::Result;
use thiserror::Error;
use winget_types::{
    PackageVersion,
    installer::VALID_FILE_EXTENSIONS,
    url::{DecodedUrl, ReleaseNotesUrl},
};

use super::UpdateVersionStrategyResult;
use crate::{
    github::{GitHubError, client::GitHub},
    manifests::Url,
};

const GITHUB_HOST: &str = "github.com";

#[derive(Error, Debug)]
pub enum GithubReleasesError {
    #[error("Not a github-releases URL (expected https://github.com/OWNER/REPO)")]
    NotGithubReleasesUrl,
    #[error("Could not parse GitHub release tag '{0}' as a package version")]
    InvalidReleaseTag(String),
    #[error("Latest release for {owner}/{repo} has no downloadable assets")]
    NoDownloadableAssets { owner: String, repo: String },
    #[error(transparent)]
    GitHub(#[from] GitHubError),
}

pub async fn resolve(
    github: &GitHub,
    source_url: &DecodedUrl,
) -> Result<UpdateVersionStrategyResult, GithubReleasesError> {
    if source_url.scheme() != "https" || source_url.host_str() != Some(GITHUB_HOST) {
        return Err(GithubReleasesError::NotGithubReleasesUrl);
    }

    let mut parts = source_url
        .path_segments()
        .ok_or(GithubReleasesError::NotGithubReleasesUrl)?
        .filter(|segment| !segment.is_empty());
    let owner = parts
        .next()
        .ok_or(GithubReleasesError::NotGithubReleasesUrl)?;
    let repo = parts
        .next()
        .ok_or(GithubReleasesError::NotGithubReleasesUrl)?;

    let release = github.get_latest_release(owner, repo).await?;
    let package_version = release
        .tag_name
        .trim_start_matches(['v', 'V'])
        .parse::<PackageVersion>()
        .or_else(|_| release.tag_name.parse::<PackageVersion>())
        .map_err(|_| GithubReleasesError::InvalidReleaseTag(release.tag_name.clone()))?;

    let urls = release
        .assets
        .into_iter()
        .map(|asset| asset.browser_download_url)
        .filter(|url| {
            let Some(extension) = url
                .path_segments()
                .and_then(|mut segments| segments.next_back())
                .filter(|name| !name.is_empty())
                .and_then(|name| Utf8Path::new(name).extension())
                .map(str::to_ascii_lowercase)
            else {
                return false;
            };

            VALID_FILE_EXTENSIONS.contains(&extension.as_str())
        })
        .map(Url::from)
        .collect::<Vec<_>>();

    if urls.is_empty() {
        return Err(GithubReleasesError::NoDownloadableAssets {
            owner: owner.to_string(),
            repo: repo.to_string(),
        });
    }

    Ok(UpdateVersionStrategyResult {
        package_version,
        urls,
        release_notes_url: release.html_url.as_str().parse::<ReleaseNotesUrl>().ok(),
        should_update: true,
        skip_version_check: false,
        observed_state: None,
    })
}
