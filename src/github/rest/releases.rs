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
}

#[derive(Debug, Deserialize)]
pub struct ReleaseAsset {
    pub browser_download_url: DecodedUrl,
}

impl GitHub {
    pub async fn get_latest_release(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<LatestRelease, GitHubError> {
        let endpoint = format!("{REST_API_URL}/repos/{owner}/{repo}/releases/latest");

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
