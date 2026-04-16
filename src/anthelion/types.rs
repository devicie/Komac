use napi_derive::napi;

/// Options for update version.
#[napi(object)]
pub struct UpdateVersionOptions {
    /// The package's unique identifier (e.g. "Microsoft.VisualStudioCode")
    pub package_identifier: String,
    /// The new package version.
    ///
    /// You can also pass one of:
    /// - `displayVersion`
    /// - `productVersion`
    /// - `fileVersion`
    ///
    /// In that case, the version will be resolved from installer analysis.
    pub version: String,
    /// List of installer URLs (may include "|architecture" suffix)
    pub urls: Vec<String>,
    /// ZIP nested installer match patterns used during installer analysis.
    /// These matches also affect `displayVersion`, `productVersion`, and
    /// `fileVersion` version selector resolution.
    ///
    /// Plain strings are matched as case-insensitive substrings, while values
    /// containing glob metacharacters are matched as glob patterns.
    pub installer_matches: Option<Vec<String>>,
    /// URL to the release notes
    pub release_notes_url: Option<String>,
    /// Release notes text for the manifest
    pub release_notes: Option<String>,
    /// Run without submitting a PR
    pub dry_run: Option<bool>,
    /// Version to replace (use "latest" for the latest version)
    pub replace: Option<String>,
    /// Look for the package under fonts instead of probing manifests first
    pub font: Option<bool>,
    /// GitHub personal access token with the `public_repo` scope
    pub token: Option<String>,
}

/// Options for get existing pull request.
#[napi(object)]
pub struct GetExistingPullRequestOptions {
    /// The package's unique identifier (e.g. "Microsoft.VisualStudioCode")
    pub package_identifier: String,
    /// The package version to search for
    pub version: String,
    /// GitHub personal access token with the `public_repo` scope.
    /// If omitted, `GITHUB_TOKEN` from the environment is used.
    pub token: Option<String>,
    /// Ignore pull requests not created by the authenticated user.
    pub ignore_pull_requests_created_by_other_users: Option<bool>,
}

/// Existing pull request metadata.
#[napi(object)]
pub struct ExistingPullRequestResult {
    /// The URL of the existing pull request
    pub pull_request_url: String,
    /// The GitHub login of the user or bot that created the pull request
    pub created_by: String,
    /// Whether the pull request was created by the authenticated user
    pub created_by_authenticated_user: bool,
    /// The current state of the pull request (`open`, `closed`, or `merged`)
    pub state: String,
    /// The pull request creation timestamp in RFC3339 format
    pub created_at: String,
}

/// Result of the update version operation.
#[napi(object)]
pub struct UpdateVersionResult {
    /// The URL of the created pull request, if submitted
    pub pull_request_url: Option<String>,
    /// The generated manifest changes as a list of (path, content) pairs
    pub changes: Vec<ManifestChange>,
    /// The package identifier that was updated
    pub package_identifier: String,
    /// The version that was created
    pub version: String,
}

/// A single manifest file change.
#[napi(object)]
pub struct ManifestChange {
    /// The file path within the winget-pkgs repository
    pub path: String,
    /// The YAML content of the manifest
    pub content: String,
}

/// Result of the analyze installer operation.
#[napi(object)]
pub struct AnalyzeInstallerResult {
    /// Detected installer information.
    pub analysis: Vec<InstallerAnalysis>,
    /// PE `FileVersion` string from the version info resource, if present.
    pub file_version: Option<String>,
    /// PE `ProductVersion` string from the version info resource, if present.
    pub product_version: Option<String>,
}

/// Installer information detected during analysis.
#[napi(object)]
pub struct InstallerAnalysis {
    /// Installer locale (if present).
    pub installer_locale: Option<String>,
    /// Installer architecture.
    pub architecture: String,
    /// Installer type (if detected).
    pub installer_type: Option<String>,
    /// Nested installer type (if present).
    pub nested_installer_type: Option<String>,
    /// Nested installer files within archives.
    pub nested_installer_files: Vec<NestedInstallerFileAnalysis>,
    /// Apps and Features / ARP entries detected for this installer.
    pub apps_and_features_entries: Vec<AppsAndFeaturesEntryAnalysis>,
    /// Install scope (if present).
    pub scope: Option<String>,
    /// Installer download URL.
    pub installer_url: String,
    /// Installer SHA-256 hash.
    pub installer_sha256: String,
    /// Installer release date, if available.
    pub release_date: Option<String>,
}

/// Apps and Features / ARP entry information detected during analysis.
#[napi(object)]
pub struct AppsAndFeaturesEntryAnalysis {
    /// Display name registered in Apps and Features, if present.
    pub display_name: Option<String>,
    /// Publisher registered in Apps and Features, if present.
    pub publisher: Option<String>,
    /// Display version registered in Apps and Features, if present.
    pub display_version: Option<String>,
    /// Product code registered in Apps and Features, if present.
    pub product_code: Option<String>,
    /// Upgrade code registered in Apps and Features, if present.
    pub upgrade_code: Option<String>,
    /// Installer type registered in Apps and Features, if present.
    pub installer_type: Option<String>,
}

/// Nested installer file information.
#[napi(object)]
pub struct NestedInstallerFileAnalysis {
    /// Relative path to the nested installer file.
    pub relative_file_path: String,
}
