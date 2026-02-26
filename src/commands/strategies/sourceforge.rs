use chrono::NaiveDateTime;
use color_eyre::eyre::Result;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use std::{
    sync::{LazyLock, OnceLock},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{sync::Mutex, time::sleep};
use winget_types::{
    PackageIdentifier, PackageVersion,
    installer::VALID_FILE_EXTENSIONS,
    url::{DecodedUrl, ReleaseNotesUrl},
};

use super::UpdateVersionStrategyResult;
use crate::{
    github::{GitHubError, client::GitHub},
    manifests::Url,
    token::default_headers,
};

const SOURCEFORGE_HOST: &str = "sourceforge.net";
const DATE_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
const SOURCEFORGE_REQUEST_DELAY: Duration = Duration::from_secs(1);

static LAST_SOURCEFORGE_REQUEST_AT: LazyLock<Mutex<Instant>> = LazyLock::new(|| {
    Mutex::new(
        Instant::now()
            .checked_sub(SOURCEFORGE_REQUEST_DELAY)
            .unwrap_or_else(Instant::now),
    )
});

#[derive(Error, Debug)]
pub enum SourceForgeError {
    #[error("Not a SourceForge project URL (expected https://sourceforge.net/projects/PROJECT)")]
    NotSourceForgeProjectUrl,
    #[error("Could not parse SourceForge release version from '{0}'")]
    InvalidReleaseVersion(String),
    #[error("Could not parse SourceForge release date '{0}'")]
    InvalidReleaseDate(String),
    #[error("No downloadable SourceForge URLs exist after filtering 404 responses")]
    NoDownloadableAssets,
    #[error(transparent)]
    GitHub(#[from] GitHubError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

#[derive(Deserialize)]
struct BestRelease {
    release: SourceForgeRelease,
}

#[derive(Deserialize)]
struct SourceForgeRelease {
    date: String,
    filename: String,
    url: DecodedUrl,
    release_notes_url: Option<DecodedUrl>,
}

fn sourceforge_urls(release_url: &DecodedUrl) -> Vec<Url> {
    const ARCH_MARKERS: [&str; 5] = ["x86", "x64", "arm64", "win32", "win64"];

    let release_url = release_url.as_str();
    let release_url_lower = release_url.to_ascii_lowercase();
    let Some((selected_marker, marker_start)) = ARCH_MARKERS.iter().find_map(|marker| {
        release_url_lower
            .find(marker)
            .map(|marker_start| (*marker, marker_start))
    }) else {
        return vec![Url::from(
            release_url
                .parse::<DecodedUrl>()
                .unwrap_or_else(|_| unreachable!()),
        )];
    };

    let marker_end = marker_start + selected_marker.len();
    let mut urls = vec![Url::from(
        release_url
            .parse::<DecodedUrl>()
            .unwrap_or_else(|_| unreachable!()),
    )]
    .into_iter()
    .filter(|url| is_supported_sourceforge_url(url))
    .collect::<Vec<_>>();

    for replacement in ARCH_MARKERS {
        if replacement == selected_marker {
            continue;
        }

        let mut candidate = release_url.to_string();
        candidate.replace_range(marker_start..marker_end, replacement);

        if let Ok(url) = candidate.parse::<Url>()
            && is_supported_sourceforge_url(&url)
            && !urls.contains(&url)
        {
            urls.push(url);
        }
    }

    urls
}

fn is_supported_sourceforge_url(url: &Url) -> bool {
    let Some(file_name) = url.path_segments().and_then(|segments| {
        let mut parts = segments
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>();
        if parts.last() == Some(&"download") {
            parts.pop();
        }
        parts.pop()
    }) else {
        return false;
    };

    let Some(extension) = file_name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
    else {
        return false;
    };

    VALID_FILE_EXTENSIONS.contains(&extension.as_str())
}

fn package_version_from_release_filename(filename: &str) -> Option<PackageVersion> {
    let segments = filename
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();

    // Parent folder is usually the canonical version directory on SourceForge.
    for segment in segments.iter().rev().skip(1) {
        let normalized = segment.trim_start_matches(['v', 'V']);
        if normalized
            .chars()
            .next()
            .map(|first| first.is_ascii_digit())
            .unwrap_or(false)
            && let Ok(version) = normalized.parse::<PackageVersion>()
        {
            return Some(version);
        }
    }

    static VERSION_RE: OnceLock<Regex> = OnceLock::new();
    let version_re = VERSION_RE
        .get_or_init(|| Regex::new(r"(?i)v?\d+(?:\.\d+)+").unwrap_or_else(|_| unreachable!()));

    for segment in segments.iter().rev() {
        if let Some(found) = version_re.find(segment) {
            let candidate = found.as_str().trim_start_matches(['v', 'V']);
            if let Ok(version) = candidate.parse::<PackageVersion>() {
                return Some(version);
            }
        }
    }

    None
}

async fn wait_for_rate_limit(last_request_at: &Mutex<Instant>, rate_limit_delay: Duration) {
    let mut last_request_at = last_request_at.lock().await;
    let time_since_last_request = Instant::now().duration_since(*last_request_at);

    if time_since_last_request < rate_limit_delay {
        sleep(rate_limit_delay - time_since_last_request).await;
    }

    *last_request_at = Instant::now();
}

async fn sourceforge_rate_limited_send(
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, reqwest::Error> {
    wait_for_rate_limit(&LAST_SOURCEFORGE_REQUEST_AT, SOURCEFORGE_REQUEST_DELAY).await;
    request.send().await
}

pub async fn resolve(
    github: &GitHub,
    package_identifier: &PackageIdentifier,
    latest_version: &PackageVersion,
    source_url: &DecodedUrl,
) -> Result<UpdateVersionStrategyResult, SourceForgeError> {
    if source_url.scheme() != "https" || source_url.host_str() != Some(SOURCEFORGE_HOST) {
        return Err(SourceForgeError::NotSourceForgeProjectUrl);
    }

    let mut path_segments = source_url
        .path_segments()
        .ok_or(SourceForgeError::NotSourceForgeProjectUrl)?
        .filter(|segment| !segment.is_empty());

    if path_segments.next() != Some("projects") {
        return Err(SourceForgeError::NotSourceForgeProjectUrl);
    }

    let project = path_segments
        .next()
        .ok_or(SourceForgeError::NotSourceForgeProjectUrl)?;

    if path_segments.next().is_some() {
        return Err(SourceForgeError::NotSourceForgeProjectUrl);
    }

    let endpoint = format!("https://{SOURCEFORGE_HOST}/projects/{project}/best_release.json");
    let client = Client::builder()
        .default_headers(default_headers(None))
        .user_agent("Mozilla/5.0 (Windows NT 10.0)") // Return Windows download url
        .build()?;

    // Probe candidate asset URLs with the default headers client. A Windows UA can
    // make missing assets look successful by redirecting to a generic files page.
    let probe_client = Client::builder()
        .default_headers(default_headers(None))
        .build()?;

    let best_release = sourceforge_rate_limited_send(client.get(endpoint))
        .await?
        .error_for_status()?
        .json::<BestRelease>()
        .await?;

    let release = best_release.release;
    let candidate_urls = sourceforge_urls(&release.url);
    let files_root_path = format!("/projects/{project}/files/");
    let mut urls = Vec::new();
    for url in &candidate_urls {
        let url = url.clone();
        match sourceforge_rate_limited_send(probe_client.head(url.as_str())).await {
            Ok(response)
                if !response.status().is_success() || response.url().path() == files_root_path => {}
            Ok(_) => {
                urls.push(url);
            }
            Err(_) => {}
        }
    }

    if urls.is_empty() {
        return Err(SourceForgeError::NoDownloadableAssets);
    }

    let package_version = package_version_from_release_filename(&release.filename)
        .or_else(|| {
            candidate_urls
                .iter()
                .find_map(|url| package_version_from_release_filename(url.path()))
        })
        .or_else(|| {
            urls.iter()
                .find_map(|url| package_version_from_release_filename(url.path()))
        })
        .ok_or_else(|| SourceForgeError::InvalidReleaseVersion(release.filename.clone()))?;

    let release_date = NaiveDateTime::parse_from_str(&release.date, DATE_FORMAT)
        .map_err(|_| SourceForgeError::InvalidReleaseDate(release.date.clone()))?
        .date();

    let manifests = github
        .get_manifests(package_identifier, latest_version)
        .await?;

    let should_update = match manifests.installer.release_date {
        Some(manifest_release_date) => release_date > manifest_release_date,
        None => {
            tracing::info!(
                package = %package_identifier,
                source_version = %package_version,
                latest_version = %latest_version,
                "No release date in manifest; skipping date check and comparing versions instead"
            );
            package_version > *latest_version
        }
    };

    Ok(UpdateVersionStrategyResult {
        package_version,
        urls,
        release_notes_url: release
            .release_notes_url
            .and_then(|url| url.as_str().parse::<ReleaseNotesUrl>().ok()),
        observed_state: None,
        should_update,
        skip_version_check: false,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        time::{Duration, Instant},
    };

    use crate::manifests::Url;
    use tokio::sync::Mutex;
    use winget_types::url::DecodedUrl;

    use super::{
        SourceForgeError, is_supported_sourceforge_url, package_version_from_release_filename,
        sourceforge_urls, wait_for_rate_limit,
    };

    #[test]
    fn accepts_project_root_urls() {
        let url =
            DecodedUrl::from_str("https://sourceforge.net/projects/crystaldiskinfo/").unwrap();

        let mut segments = url
            .path_segments()
            .unwrap()
            .filter(|segment| !segment.is_empty());
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("sourceforge.net"));
        assert_eq!(segments.next(), Some("projects"));
        assert_eq!(segments.next(), Some("crystaldiskinfo"));
        assert!(segments.next().is_none());
    }

    #[test]
    fn rejects_non_project_urls() {
        let url = DecodedUrl::from_str("https://sourceforge.net/projects/").unwrap();
        let mut segments = url
            .path_segments()
            .unwrap()
            .filter(|segment| !segment.is_empty());
        assert_eq!(segments.next(), Some("projects"));
        assert_eq!(segments.next(), None);

        let error = SourceForgeError::NotSourceForgeProjectUrl;
        assert_eq!(
            error.to_string(),
            "Not a SourceForge project URL (expected https://sourceforge.net/projects/PROJECT)"
        );
    }

    #[test]
    fn extracts_version_from_nested_sourceforge_path() {
        let filename = "/sdcc-win64/4.5.0/sdcc-4.5.0-x64-setup.exe";
        let version = package_version_from_release_filename(filename).unwrap();
        assert_eq!(version.as_str(), "4.5.0");
    }

    #[test]
    fn prefers_immediate_parent_over_older_folders() {
        let filename = "/3. Alpha Releases/1.7.1/Frhed-1.7.1-Setup.exe";
        let version = package_version_from_release_filename(filename).unwrap();
        assert_eq!(version.as_str(), "1.7.1");
    }

    #[test]
    fn extracts_version_from_non_numeric_parent_segment() {
        let filename = "/Windows/hugin-2025.0/hugin-2025.0-win64.exe";
        let version = package_version_from_release_filename(filename).unwrap();
        assert_eq!(version.as_str(), "2025.0");
    }

    #[test]
    fn expands_x86_release_url_to_arch_variants() {
        let release_url =
            DecodedUrl::from_str("https://downloads.sourceforge.net/project/foo/foo-1.2.3-x86.exe")
                .unwrap();

        let urls = sourceforge_urls(&release_url)
            .into_iter()
            .map(|url| url.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            urls,
            vec![
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-x86.exe",
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-x64.exe",
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-arm64.exe",
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-win32.exe",
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-win64.exe",
            ]
        );
    }

    #[test]
    fn expands_win64_release_url_to_arch_variants() {
        let release_url = DecodedUrl::from_str(
            "https://downloads.sourceforge.net/project/foo/foo-1.2.3-win64.exe",
        )
        .unwrap();

        let urls = sourceforge_urls(&release_url)
            .into_iter()
            .map(|url| url.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            urls,
            vec![
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-win64.exe",
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-x86.exe",
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-x64.exe",
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-arm64.exe",
                "https://downloads.sourceforge.net/project/foo/foo-1.2.3-win32.exe",
            ]
        );
    }

    #[test]
    fn keeps_single_url_when_no_arch_marker() {
        let release_url =
            DecodedUrl::from_str("https://downloads.sourceforge.net/project/foo/foo-1.2.3.exe")
                .unwrap();

        let urls = sourceforge_urls(&release_url)
            .into_iter()
            .map(|url| url.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            urls,
            vec!["https://downloads.sourceforge.net/project/foo/foo-1.2.3.exe"]
        );
    }

    #[test]
    fn rejects_unsupported_sourceforge_asset_extension() {
        let url = "https://downloads.sourceforge.net/project/foo/foo-x64.dll"
            .parse::<Url>()
            .unwrap();
        assert!(!is_supported_sourceforge_url(&url));
    }

    #[tokio::test]
    async fn rate_limit_waits_between_requests() {
        let delay = Duration::from_millis(100);
        let last_request_at = Mutex::new(Instant::now().checked_sub(delay).unwrap());

        wait_for_rate_limit(&last_request_at, delay).await;
        let start = Instant::now();
        wait_for_rate_limit(&last_request_at, delay).await;

        assert!(
            start.elapsed() >= Duration::from_millis(90),
            "expected a wait close to {delay:?}, waited {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn rate_limit_updates_last_request_time() {
        let delay = Duration::from_millis(50);
        let last_request_at = Mutex::new(Instant::now().checked_sub(delay).unwrap());

        wait_for_rate_limit(&last_request_at, delay).await;
        let elapsed_since_record = Instant::now().duration_since(*last_request_at.lock().await);

        assert!(
            elapsed_since_record < Duration::from_millis(30),
            "expected request timestamp to be recorded close to now, was {:?}",
            elapsed_since_record
        );
    }
}
