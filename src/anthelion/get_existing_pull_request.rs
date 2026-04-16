use napi::bindgen_prelude::*;
use napi_derive::napi;
use winget_types::{PackageIdentifier, PackageVersion};

use super::{
    token::resolve_github_token,
    types::{ExistingPullRequestResult, GetExistingPullRequestOptions},
};
use crate::github::{client::GitHub, graphql::types::PullRequestState};

/// Get an existing pull request for a package version in winget-pkgs.
///
/// # Errors
///
/// Returns `InvalidArg` if `package_identifier` or `version` are invalid.
/// Returns `GenericFailure` if creating the GitHub client or querying pull requests fails.
#[napi]
pub async fn get_existing_pull_request(
    options: GetExistingPullRequestOptions,
) -> napi::Result<Option<ExistingPullRequestResult>> {
    let package_identifier: PackageIdentifier =
        options.package_identifier.parse().map_err(|e| {
            Error::new(
                Status::InvalidArg,
                format!("Invalid package identifier: {e}"),
            )
        })?;

    let package_version: PackageVersion = options
        .version
        .parse()
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid package version: {e}")))?;

    let token = resolve_github_token(options.token.as_deref())?;

    let github = GitHub::new(&token).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to create GitHub client: {e}"),
        )
    })?;

    let ignore_other_users = options
        .ignore_pull_requests_created_by_other_users
        .unwrap_or_default();
    let pull_request = github
        .get_existing_pull_request(&package_identifier, &package_version, ignore_other_users)
        .await
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to get existing pull request: {e}"),
            )
        })?;

    let Some(pull_request) = pull_request else {
        return Ok(None);
    };

    let created_by = pull_request.author_login().cloned().unwrap_or_default();

    Ok(Some(ExistingPullRequestResult {
        pull_request_url: pull_request.url.to_string(),
        created_by,
        created_by_authenticated_user: pull_request.viewer_did_author,
        state: match pull_request.state {
            PullRequestState::Open => "open",
            PullRequestState::Closed => "closed",
            PullRequestState::Merged => "merged",
        }
        .to_string(),
        created_at: pull_request.created_at.to_rfc3339(),
    }))
}
