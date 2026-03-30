use reqwest::header::ACCEPT;
use serde::Deserialize;
use winget_types::url::DecodedUrl;

use super::{
    super::{GitHubError, client::GitHub},
    GITHUB_JSON_MIME, REST_API_URL, REST_API_VERSION, X_GITHUB_API_VERSION,
};

#[derive(Debug, Deserialize)]
pub struct LatestRelease {
    pub tag_name: String,
    pub html_url: DecodedUrl,
    pub assets: Vec<ReleaseAsset>,
    pub prerelease: bool,
    pub draft: bool,
}

#[derive(Debug, Deserialize)]
pub struct ReleaseAsset {
    pub browser_download_url: DecodedUrl,
}

impl GitHub {
    pub async fn get_releases(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<LatestRelease>, GitHubError> {
        let endpoint = format!("{REST_API_URL}/repos/{owner}/{repo}/releases?per_page=30");

        let response = self
            .0
            .get(endpoint)
            .header(ACCEPT, GITHUB_JSON_MIME)
            .header(X_GITHUB_API_VERSION, REST_API_VERSION)
            .send()
            .await?
            .error_for_status()?;

        Ok(response.json::<Vec<LatestRelease>>().await?)
    }

    pub async fn get_release_by_tag(
        &self,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> Result<LatestRelease, GitHubError> {
        let endpoint = format!("{REST_API_URL}/repos/{owner}/{repo}/releases/tags/{tag}");

        let response = self
            .0
            .get(endpoint)
            .header(ACCEPT, GITHUB_JSON_MIME)
            .header(X_GITHUB_API_VERSION, REST_API_VERSION)
            .send()
            .await?
            .error_for_status()?;

        Ok(response.json::<LatestRelease>().await?)
    }
}
