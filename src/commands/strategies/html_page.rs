use std::{collections::HashSet, sync::OnceLock};

use camino::Utf8Path;
use color_eyre::eyre::Result;
use regex::Regex;
use reqwest::Client;
use thiserror::Error;
use winget_types::{PackageVersion, installer::VALID_FILE_EXTENSIONS, url::DecodedUrl};

use super::UpdateVersionStrategyResult;
use crate::manifests::Url;

#[derive(Error, Debug)]
pub enum HtmlPageError {
    #[error("No downloadable URLs found on page {0}")]
    NoDownloadableUrls(DecodedUrl),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

pub async fn resolve(
    latest_version: &PackageVersion,
    page_url: &DecodedUrl,
) -> Result<UpdateVersionStrategyResult, HtmlPageError> {
    let client = Client::new();
    let html = client
        .get(page_url.as_str())
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let urls = extract_installer_urls(&html, page_url);

    if urls.is_empty() {
        return Err(HtmlPageError::NoDownloadableUrls(page_url.clone()));
    }

    Ok(UpdateVersionStrategyResult {
        // HTML pages do not provide an explicit version, so reuse the latest known version.
        package_version: latest_version.clone(),
        urls,
        release_notes_url: None,
        observed_state: None,
        should_update: true,
        skip_version_check: true,
    })
}

fn extract_installer_urls(html: &str, base_url: &DecodedUrl) -> Vec<Url> {
    static HREF_RE: OnceLock<Regex> = OnceLock::new();
    let href_re = HREF_RE.get_or_init(|| {
        Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).unwrap_or_else(|_| unreachable!())
    });

    let mut urls = Vec::new();
    let mut seen = HashSet::new();

    for capture in href_re.captures_iter(html) {
        let href = &capture[1];

        let Some(resolved) = base_url.join(href).ok() else {
            continue;
        };

        let has_valid_extension = resolved
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .filter(|name| !name.is_empty())
            .and_then(|name| Utf8Path::new(name).extension())
            .map(str::to_ascii_lowercase)
            .is_some_and(|ext| VALID_FILE_EXTENSIONS.contains(&ext.as_str()));

        if has_valid_extension && seen.insert(resolved.to_string()) {
            if let Ok(decoded) = resolved.as_str().parse::<DecodedUrl>() {
                urls.push(Url::from(decoded));
            }
        }
    }

    urls
}

#[cfg(test)]
mod tests {
    use super::extract_installer_urls;
    use winget_types::url::DecodedUrl;

    #[test]
    fn extracts_absolute_urls() {
        let html = r#"
            <a href="https://example.com/app-x64.exe">64-bit</a>
            <a href="https://example.com/app-arm64.msi">ARM64</a>
            <a href="https://example.com/readme.txt">Readme</a>
        "#;
        let base = "https://example.com/downloads/"
            .parse::<DecodedUrl>()
            .unwrap();
        let urls = extract_installer_urls(html, &base);
        assert_eq!(urls.len(), 2);
        assert!(urls[0].as_str().ends_with(".exe"));
        assert!(urls[1].as_str().ends_with(".msi"));
    }

    #[test]
    fn resolves_relative_urls() {
        let html = r#"<a href="../files/setup.exe">Download</a>"#;
        let base = "https://example.com/downloads/page/"
            .parse::<DecodedUrl>()
            .unwrap();
        let urls = extract_installer_urls(html, &base);
        assert_eq!(urls.len(), 1);
        assert_eq!(
            urls[0].as_str(),
            "https://example.com/downloads/files/setup.exe"
        );
    }

    #[test]
    fn deduplicates_urls() {
        let html = r#"
            <a href="https://example.com/app.exe">Link 1</a>
            <a href="https://example.com/app.exe">Link 2</a>
        "#;
        let base = "https://example.com/".parse::<DecodedUrl>().unwrap();
        let urls = extract_installer_urls(html, &base);
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn ignores_unsupported_extensions() {
        let html = r#"
            <a href="https://example.com/file.pdf">PDF</a>
            <a href="https://example.com/file.dmg">macOS</a>
            <a href="https://example.com/file.deb">Linux</a>
        "#;
        let base = "https://example.com/".parse::<DecodedUrl>().unwrap();
        let urls = extract_installer_urls(html, &base);
        assert!(urls.is_empty());
    }

    #[test]
    fn handles_all_valid_extensions() {
        let html = r#"
            <a href="/app.msix">MSIX</a>
            <a href="/app.msi">MSI</a>
            <a href="/app.appx">APPX</a>
            <a href="/app.exe">EXE</a>
            <a href="/app.zip">ZIP</a>
            <a href="/app.msixbundle">MSIX Bundle</a>
            <a href="/app.appxbundle">APPX Bundle</a>
        "#;
        let base = "https://example.com/".parse::<DecodedUrl>().unwrap();
        let urls = extract_installer_urls(html, &base);
        assert_eq!(urls.len(), 7);
    }
}
