use chrono::{DateTime, Utc};
use color_eyre::eyre::Result;
use reqwest::{
    Client, StatusCode,
    header::{HeaderName, LAST_MODIFIED},
};
use thiserror::Error;
use winget_types::{PackageIdentifier, PackageVersion, url::DecodedUrl};

use super::UpdateVersionStrategyResult;
use crate::{
    github::{GitHubError, client::GitHub},
    manifests::Url,
};

// Header and State allow custom change detection, instead of having to download and check the hash
#[derive(Error, Debug)]
pub enum VanityUrlError {
    #[error("--header and --state must be provided together")]
    HeaderStatePairRequired,
    #[error("Invalid header name: {0}")]
    InvalidHeaderName(String),
    #[error("No {header} header found for {url}")]
    MissingHeader { header: String, url: DecodedUrl },
    #[error("No Last-Modified header found for {0}")]
    MissingLastModified(DecodedUrl),
    #[error(transparent)]
    GitHub(#[from] GitHubError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

pub async fn resolve(
    github: &GitHub,
    package_identifier: &PackageIdentifier,
    latest_version: &PackageVersion,
    source_url: &DecodedUrl,
    header: Option<&str>,
    state: Option<&str>,
) -> Result<UpdateVersionStrategyResult, VanityUrlError> {
    if header.is_some() ^ state.is_some() {
        return Err(VanityUrlError::HeaderStatePairRequired);
    }

    let client = Client::new();
    let response = client.head(source_url.as_str()).send().await?;
    let response = if response.status() == StatusCode::METHOD_NOT_ALLOWED
        || response.status() == StatusCode::NOT_FOUND
    {
        client.get(source_url.as_str()).send().await?
    } else {
        response
    }
    .error_for_status()?;

    let mut observed_state = None;

    let should_update = if let (Some(header), Some(state)) = (header, state) {
        let header_name = HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| VanityUrlError::InvalidHeaderName(header.to_string()))?;

        let actual_state = response
            .headers()
            .get(&header_name)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| VanityUrlError::MissingHeader {
                header: header_name.to_string(),
                url: source_url.clone(),
            })?;

        observed_state = Some(actual_state.to_owned());
        actual_state != state
    } else {
        let last_modified = response
            .headers()
            .get(LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| DateTime::parse_from_rfc2822(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .ok_or_else(|| VanityUrlError::MissingLastModified(source_url.clone()))?;

        let manifests = github
            .get_manifests(package_identifier, latest_version)
            .await?;

        manifests
            .installer
            .release_date
            .map_or(true, |manifest_release_date| {
                // Manifest release dates are day-granularity; treat same-day Last-Modified as updated.
                last_modified.date_naive() >= manifest_release_date
            })
    };

    Ok(UpdateVersionStrategyResult {
        // Vanity URLs do not provide an explicit version, so update the latest known version.
        package_version: latest_version.clone(),
        urls: vec![Url::from(source_url.clone())],
        release_notes_url: None,
        observed_state,
        should_update,
        skip_version_check: true,
    })
}
