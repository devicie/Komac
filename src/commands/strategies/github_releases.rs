use std::{
    collections::HashMap,
    sync::{LazyLock, OnceLock},
};

use camino::Utf8Path;
use color_eyre::eyre::Result;
use regex::Regex;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::debug;
use winget_types::{
    PackageIdentifier, PackageVersion,
    installer::VALID_FILE_EXTENSIONS,
    url::{DecodedUrl, ReleaseNotesUrl},
};

use super::UpdateVersionStrategyResult;
use crate::{
    github::{GitHubError, client::GitHub},
    manifests::Url,
    traits::AsciiExt,
};

const GITHUB_HOST: &str = "github.com";
const PRE_RELEASE_CHANNELS: [&str; 6] = ["alpha", "beta", "preview", "pre", "nightly", "rc"];

static LATEST_RELEASE_CACHE: LazyLock<Mutex<HashMap<String, CachedGithubRelease>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
struct CachedGithubRelease {
    package_version: PackageVersion,
    urls: Vec<Url>,
    release_notes_url: Option<ReleaseNotesUrl>,
}

#[derive(Debug, Clone)]
struct ReleaseFilterDiagnostics {
    total_releases: usize,
    total_non_draft: usize,
    skipped_draft: usize,
    skipped_channel_mismatch: usize,
    skipped_no_version: Vec<String>, // First few tags that couldn't be parsed
    skipped_no_windows_assets: usize,
    found_prerelease_fallback: bool,
}

impl ReleaseFilterDiagnostics {
    fn new() -> Self {
        Self {
            total_releases: 0,
            total_non_draft: 0,
            skipped_draft: 0,
            skipped_channel_mismatch: 0,
            skipped_no_version: Vec::new(),
            skipped_no_windows_assets: 0,
            found_prerelease_fallback: false,
        }
    }
}

#[derive(Error, Debug)]
pub enum GithubReleasesError {
    #[error("Not a github-releases URL (expected https://github.com/OWNER/REPO)")]
    NotGithubReleasesUrl,
    #[error("No suitable release found for {owner}/{repo}")]
    NoSuitableRelease {
        owner: String,
        repo: String,
        diagnostics: String,
    },
    #[error(transparent)]
    GitHub(#[from] GitHubError),
}

fn detect_channel(package_id: &str) -> Option<&'static str> {
    package_id
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|segment| !segment.is_empty())
        .find_map(|segment| {
            PRE_RELEASE_CHANNELS
                .iter()
                .copied()
                .find(|&channel| segment.eq_ignore_ascii_case(channel))
        })
}

fn release_tag_from_download_url(source_url: &DecodedUrl) -> Option<String> {
    let segments = source_url.path_segments()?.collect::<Vec<_>>();
    if segments.len() < 5 {
        return None;
    }

    if segments[2].eq_ignore_ascii_case("releases") && segments[3].eq_ignore_ascii_case("download")
    {
        Some(segments[4].to_string())
    } else {
        None
    }
}

fn has_prerelease_suffix(tag: &str) -> bool {
    static PRE_RELEASE_SUFFIX_RE: OnceLock<Regex> = OnceLock::new();
    let pre_release_suffix_re = PRE_RELEASE_SUFFIX_RE.get_or_init(|| {
        // Treat tags like "1.2.3-rc4" and "2.0.2-b7" as prereleases.
        Regex::new(r"(?i)(?:^|[-._])(rc|b)\d+(?:$|[-._])").unwrap_or_else(|_| unreachable!())
    });

    pre_release_suffix_re.is_match(tag)
}

fn is_prerelease_release(tag: &str, is_marked_prerelease: bool) -> bool {
    is_marked_prerelease
        || PRE_RELEASE_CHANNELS
            .iter()
            .any(|&kw| tag.contains_ignore_ascii_case(kw))
        || has_prerelease_suffix(tag)
}

fn strip_stable_suffix(version_like: &str) -> &str {
    const STABLE_SUFFIXES: [&str; 3] = ["-release", "_release", ".release"];

    for suffix in STABLE_SUFFIXES {
        if version_like.len() <= suffix.len() {
            continue;
        }

        let start = version_like.len() - suffix.len();
        if version_like[start..].eq_ignore_ascii_case(suffix) {
            return &version_like[..start];
        }
    }

    version_like
}

fn parse_version_like(version_like: &str) -> Option<PackageVersion> {
    strip_stable_suffix(version_like)
        .trim_start_matches(['v', 'V'])
        .parse::<PackageVersion>()
        .ok()
}

fn package_version_from_tag(tag: &str) -> Option<PackageVersion> {
    let tag = tag.trim();

    static STRICT_TAG_VERSION_RE: OnceLock<Regex> = OnceLock::new();
    let strict_tag_version_re = STRICT_TAG_VERSION_RE.get_or_init(|| {
        // Accept only clean whole-tag versions here so noisy tags fall back
        // to fragment extraction (for example, v1.15.4+73-desktop -> 1.15.4).
        Regex::new(r"(?i)^v?\d+(?:\.\d+)+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?(?:[a-z][a-z0-9]*)?$")
            .unwrap_or_else(|_| unreachable!())
    });

    // Only parse the full tag directly when it is already version-shaped.
    if strict_tag_version_re.is_match(tag)
        && let Some(version) = parse_version_like(tag)
    {
        return Some(version);
    }

    static VERSION_RE: OnceLock<Regex> = OnceLock::new();
    let version_re = VERSION_RE.get_or_init(|| {
        // Match version-like fragments inside release tags, such as
        // "name-v1.2.3", "app_v0.70b-community", or "v3.0.5-beta".
        Regex::new(r"(?i)v?\d+(?:\.\d+)+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?(?:[a-z][a-z0-9]*)?")
            .unwrap_or_else(|_| unreachable!())
    });

    // Try fragment extraction first (handles complex tags)
    if let Some(version) = version_re
        .find_iter(tag)
        .filter_map(|found| parse_version_like(found.as_str()))
        .last()
    {
        return Some(version);
    }

    // Fallback: handle date-based versions (e.g., "2026-03-29" or "2026.03.29")
    static DATE_VERSION_RE: OnceLock<Regex> = OnceLock::new();
    let date_version_re = DATE_VERSION_RE.get_or_init(|| {
        // Match date patterns: YYYY-MM-DD or YYYY.MM.DD
        Regex::new(r"(\d{4})[-.](\d{2})[-.](\d{2})").unwrap_or_else(|_| unreachable!())
    });

    if let Some(caps) = date_version_re.captures(tag) {
        let year = &caps[1];
        let month = &caps[2];
        let day = &caps[3];
        let date_version = format!("{}.{}.{}", year, month, day);
        if let Ok(version) = date_version.parse::<PackageVersion>() {
            debug!(
                tag = %tag,
                version = %version,
                "Extracted date-based version from release tag"
            );
            return Some(version);
        }
    }

    None
}

pub async fn resolve(
    github: &GitHub,
    package_identifier: &PackageIdentifier,
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

    let channel = detect_channel(package_identifier.as_str());
    let cache_key = {
        let base = format!("{owner}/{repo}").to_ascii_lowercase();
        match channel {
            Some(ch) => format!("{base}#{ch}"),
            None => base,
        }
    };

    if let Some(cached_release) = LATEST_RELEASE_CACHE.lock().await.get(&cache_key).cloned() {
        debug!(
            package = %package_identifier,
            owner = owner,
            repo = repo,
            channel = ?channel,
            "Using cached release from previous lookup"
        );
        return Ok(UpdateVersionStrategyResult {
            package_version: cached_release.package_version,
            urls: cached_release.urls,
            release_notes_url: cached_release.release_notes_url,
            should_update: true,
            skip_version_check: false,
            observed_state: None,
        });
    }

    debug!(
        package = %package_identifier,
        owner = owner,
        repo = repo,
        channel = ?channel,
        "Fetching releases from GitHub"
    );

    let mut releases = github.get_releases(owner, repo).await?;
    if releases.is_empty()
        && let Some(tag) = release_tag_from_download_url(source_url)
    {
        match github.get_release_by_tag(owner, repo, &tag).await {
            Ok(release) => {
                debug!(
                    owner = owner,
                    repo = repo,
                    tag = %tag,
                    "Releases list was empty; using release-by-tag fallback"
                );
                releases.push(release);
            }
            Err(error) => {
                debug!(
                    owner = owner,
                    repo = repo,
                    tag = %tag,
                    error = %error,
                    "Releases list was empty and release-by-tag fallback failed"
                );
            }
        }
    }
    let mut diagnostics = ReleaseFilterDiagnostics::new();
    diagnostics.total_releases = releases.len();

    let mut found: Option<CachedGithubRelease> = None;
    let mut prerelease_fallback: Option<CachedGithubRelease> = None;
    let mut had_channel_match = false;

    for release in releases {
        if release.draft {
            diagnostics.skipped_draft += 1;
            debug!(tag = %release.tag_name, "Skipping draft release");
            continue;
        }

        diagnostics.total_non_draft += 1;

        let tag = &release.tag_name;
        let is_prerelease = is_prerelease_release(tag, release.prerelease);
        let matches = match channel {
            Some(ch) => tag.contains_ignore_ascii_case(ch),
            None => !is_prerelease,
        };

        if !matches {
            if is_prerelease && prerelease_fallback.is_none() {
                debug!(
                    tag = %tag,
                    is_prerelease = is_prerelease,
                    channel = ?channel,
                    "Release does not match selected channel, but is prerelease; will use as fallback if no exact match is found"
                );
            } else {
                diagnostics.skipped_channel_mismatch += 1;
                debug!(
                    tag = %tag,
                    is_prerelease = is_prerelease,
                    expected_channel = ?channel,
                    "Skipping release: channel/prerelease status does not match"
                );
                continue;
            }
        } else {
            had_channel_match = true;
        }

        let Some(package_version) = package_version_from_tag(tag) else {
            diagnostics.skipped_no_version.push(tag.clone());
            debug!(
                tag = %tag,
                "Skipping release: could not extract version from tag"
            );
            continue;
        };

        let total_assets = release.assets.len();
        let urls = release
            .assets
            .into_iter()
            .map(|asset| asset.browser_download_url)
            .filter(|url| {
                let Some(file_name) = url
                    .path_segments()
                    .and_then(|mut segments| segments.next_back())
                    .filter(|name| !name.is_empty())
                else {
                    return false;
                };

                let Some(extension) = Utf8Path::new(file_name)
                    .extension()
                    .map(str::to_ascii_lowercase)
                else {
                    return false;
                };

                let file_name_lower = file_name.to_ascii_lowercase();

                // TODO We should also check for valid portables, but this skips downloading
                let is_valid = VALID_FILE_EXTENSIONS.contains(&extension.as_str())
                    && !file_name_lower.contains("darwin")
                    && !file_name_lower.contains("linux")
                    && !file_name_lower.contains("mac")
                    && !file_name_lower.contains("osx")
                    && !file_name_lower.contains("freebsd")
                    && !file_name_lower.contains("symbols");

                if !is_valid {
                    debug!(
                        url = %url,
                        extension = %extension,
                        "Asset filtered out: invalid extension or non-Windows platform"
                    );
                }
                is_valid
            })
            .map(Url::from)
            .collect::<Vec<_>>();

        if urls.is_empty() {
            diagnostics.skipped_no_windows_assets += 1;
            debug!(
                tag = %tag,
                asset_count = total_assets,
                "Skipping release: no Windows-suitable assets found"
            );
            continue;
        }

        debug!(
            tag = %tag,
            version = %package_version,
            asset_count = urls.len(),
            "Found suitable release"
        );

        let candidate = CachedGithubRelease {
            package_version,
            urls,
            release_notes_url: release.html_url.as_str().parse::<ReleaseNotesUrl>().ok(),
        };

        if matches {
            found = Some(candidate);
            break;
        }

        diagnostics.found_prerelease_fallback = true;
        prerelease_fallback = Some(candidate);
    }

    // Only use the prerelease fallback when no release matched the target channel at all
    // (e.g. a repo that marks every release as prerelease). If channel-matching releases
    // existed but had no Windows assets, return an error instead of falling back to an
    // older prerelease that happens to have assets.
    let cached_release = if had_channel_match {
        found
    } else {
        found.or(prerelease_fallback)
    }
    .ok_or_else(|| {
        let diag_msg = format!(
            "total_releases={}, non_draft={}, \
            skipped_draft={}, skipped_channel_mismatch={}, \
            skipped_no_version_extracted={} (examples: {}), \
            skipped_no_windows_assets={}, found_prerelease_fallback={}",
            diagnostics.total_releases,
            diagnostics.total_non_draft,
            diagnostics.skipped_draft,
            diagnostics.skipped_channel_mismatch,
            diagnostics.skipped_no_version.len(),
            diagnostics
                .skipped_no_version
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            diagnostics.skipped_no_windows_assets,
            diagnostics.found_prerelease_fallback
        );

        debug!(
            owner = owner,
            repo = repo,
            channel = ?channel,
            diagnostics = %diag_msg,
            "No suitable release found after filtering releases"
        );

        GithubReleasesError::NoSuitableRelease {
            owner: owner.to_string(),
            repo: repo.to_string(),
            diagnostics: diag_msg,
        }
    })?;

    LATEST_RELEASE_CACHE
        .lock()
        .await
        .insert(cache_key, cached_release.clone());

    Ok(UpdateVersionStrategyResult {
        package_version: cached_release.package_version,
        urls: cached_release.urls,
        release_notes_url: cached_release.release_notes_url,
        should_update: true,
        skip_version_check: false,
        observed_state: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        detect_channel, has_prerelease_suffix, is_prerelease_release, package_version_from_tag,
    };

    #[test]
    fn does_not_detect_channel_inside_word() {
        assert_eq!(detect_channel("dpaulat.supercell-wx"), None);
    }

    #[test]
    fn detects_preview_channel_from_package_suffix() {
        assert_eq!(detect_channel("Dapr.CLI.Preview"), Some("preview"));
    }

    #[test]
    fn detects_rc_channel_from_package_suffix() {
        assert_eq!(detect_channel("Vendor.Tool.RC"), Some("rc"));
    }

    #[test]
    fn extracts_embedded_version_with_prefix_and_suffix() {
        let parsed = package_version_from_tag("eMule_v0.70b-community").map(|v| v.to_string());
        assert_eq!(parsed.as_deref(), Some("0.70b"));
    }

    #[test]
    fn extracts_embedded_version_after_dash_v_prefix() {
        let parsed = package_version_from_tag("note-gen-v0.27.3").map(|v| v.to_string());
        assert_eq!(parsed.as_deref(), Some("0.27.3"));
    }

    #[test]
    fn extracts_embedded_numeric_version_after_dash() {
        let parsed = package_version_from_tag("RelightLab-2026.01").map(|v| v.to_string());
        assert_eq!(parsed.as_deref(), Some("2026.01"));
    }

    #[test]
    fn extracts_embedded_version_after_dash_v_prefix_without_suffix() {
        let parsed = package_version_from_tag("web-v2026.3.0").map(|v| v.to_string());
        assert_eq!(parsed.as_deref(), Some("2026.3.0"));
    }

    #[test]
    fn strips_build_metadata_and_suffix_from_tag() {
        let parsed = package_version_from_tag("v1.15.4+73-desktop").map(|v| v.to_string());
        assert_eq!(parsed.as_deref(), Some("1.15.4"));
    }

    #[test]
    fn prefers_trailing_version_when_tag_starts_with_date() {
        let parsed = package_version_from_tag("2026-02-22-Release-2.10.3").map(|v| v.to_string());
        assert_eq!(parsed.as_deref(), Some("2.10.3"));
    }

    #[test]
    fn keeps_hyphenated_prerelease_for_plain_tag() {
        let parsed = package_version_from_tag("3.0.5-beta").map(|v| v.to_string());
        assert_eq!(parsed.as_deref(), Some("3.0.5-beta"));
    }

    #[test]
    fn keeps_hyphenated_prerelease_for_prefixed_tag() {
        let parsed = package_version_from_tag("v3.0.5-beta").map(|v| v.to_string());
        assert_eq!(parsed.as_deref(), Some("3.0.5-beta"));
    }

    #[test]
    fn strips_release_suffix_for_prefixed_tag() {
        let parsed = package_version_from_tag("v0.5.5-release").map(|v| v.to_string());
        assert_eq!(parsed.as_deref(), Some("0.5.5"));
    }

    #[test]
    fn detects_release_candidate_suffix_as_prerelease() {
        assert!(has_prerelease_suffix("1.2.3-rc4"));
    }

    #[test]
    fn detects_beta_suffix_as_prerelease() {
        assert!(has_prerelease_suffix("2.0.2-b7"));
    }

    #[test]
    fn ignores_plain_stable_version_for_suffix_detection() {
        assert!(!has_prerelease_suffix("1.2.3"));
    }

    #[test]
    fn release_marked_prerelease_is_prerelease() {
        assert!(is_prerelease_release("1.2.3", true));
    }

    #[test]
    fn release_with_channel_keyword_is_prerelease() {
        assert!(is_prerelease_release("v1.2.3-preview", false));
    }

    #[test]
    fn plain_release_without_marker_or_suffix_is_not_prerelease() {
        assert!(!is_prerelease_release("1.2.3", false));
    }
}
