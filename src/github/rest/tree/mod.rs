mod git_file_mode;
mod object;
mod r#type;

use std::collections::BTreeSet;

use color_eyre::eyre::eyre;
use futures_util::{StreamExt, stream};
pub use git_file_mode::GitFileMode;
use itertools::Itertools;
pub use object::TreeObject;
use reqwest::header::ACCEPT;
use serde::{Deserialize, Serialize};
pub use r#type::TreeType;
use winget_types::{PackageIdentifier, PackageVersion};

use super::{
    super::{GitHubError, MICROSOFT, WINGET_PKGS, client::GitHub, utils::PackagePath},
    GITHUB_JSON_MIME, REST_API_URL, REST_API_VERSION, X_GITHUB_API_VERSION,
};

/// A Git Tree which represents the hierarchy between files in a Git repository.
#[derive(Serialize, Deserialize)]
pub struct GitTree {
    pub sha: String,
    pub url: String,
    pub truncated: bool,
    pub tree: Vec<TreeObject>,
}

impl GitHub {
    pub async fn get_package_identifiers_for_letter(
        &self,
        letter: Option<char>,
    ) -> Result<BTreeSet<PackageIdentifier>, GitHubError> {
        let mut first_level_paths = if let Some(letter) = letter {
            vec![format!("manifests/{}", letter.to_ascii_lowercase())]
        } else {
            let root = self
                .get_git_tree(MICROSOFT, WINGET_PKGS, "manifests", false)
                .await?;

            root.tree
                .iter()
                .filter(|entry| entry.is_tree())
                .map(|entry| format!("manifests/{}", entry.path))
                .collect::<Vec<_>>()
        };

        first_level_paths.sort_unstable();

        let package_identifiers =
            stream::iter(first_level_paths.into_iter().map(|path| async move {
                self.collect_package_identifiers_from_path(MICROSOFT, WINGET_PKGS, &path)
                    .await
            }))
            .buffer_unordered(6)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .try_fold(BTreeSet::new(), |mut acc, result| {
                let identifiers = result?;
                acc.extend(identifiers);
                Ok::<_, GitHubError>(acc)
            })?;

        if package_identifiers.is_empty() {
            Err(GitHubError::GraphQL(eyre!(
                "failed to enumerate package identifiers from winget-pkgs"
            )))
        } else {
            Ok(package_identifiers)
        }
    }

    async fn collect_package_identifiers_from_path(
        &self,
        owner: &str,
        repo: &str,
        root_path: &str,
    ) -> Result<BTreeSet<PackageIdentifier>, GitHubError> {
        let mut package_identifiers = BTreeSet::new();
        let mut stack = vec![root_path.to_owned()];

        while let Some(path) = stack.pop() {
            let recursive_tree = self.get_git_tree(owner, repo, &path, true).await?;

            if !recursive_tree.truncated {
                package_identifiers.extend(parse_package_identifiers(&recursive_tree.tree));
                continue;
            }

            let non_recursive_tree = self.get_git_tree(owner, repo, &path, false).await?;
            let subdirectories = non_recursive_tree
                .tree
                .iter()
                .filter(|entry| entry.is_tree())
                .map(|entry| format!("{path}/{}", entry.path))
                .collect::<Vec<_>>();

            if subdirectories.is_empty() {
                package_identifiers.extend(parse_package_identifiers(&recursive_tree.tree));
                continue;
            }

            stack.extend(subdirectories);
        }

        Ok(package_identifiers)
    }

    async fn get_git_tree(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        recursive: bool,
    ) -> Result<GitTree, GitHubError> {
        let endpoint = if recursive {
            format!("{REST_API_URL}/repos/{owner}/{repo}/git/trees/HEAD:{path}?recursive=1")
        } else {
            format!("{REST_API_URL}/repos/{owner}/{repo}/git/trees/HEAD:{path}")
        };

        let response = self
            .0
            .get(endpoint)
            .header(ACCEPT, GITHUB_JSON_MIME)
            .header(X_GITHUB_API_VERSION, REST_API_VERSION)
            .send()
            .await?
            .error_for_status()?;

        Ok(response.json::<GitTree>().await?)
    }

    pub async fn get_versions(
        &self,
        package_identifier: &PackageIdentifier,
    ) -> Result<BTreeSet<PackageVersion>, GitHubError> {
        self.get_all_versions(
            MICROSOFT,
            WINGET_PKGS,
            PackagePath::new(package_identifier, None, None),
        )
        .await
        .map_err(|_| GitHubError::PackageNonExistent(package_identifier.clone()))
    }

    /// Returns all valid package versions under a specific repository path
    ///
    /// This function inspects the Git tree at the given path in the target repository, identifies
    /// directories corresponding to version folders, and returns all versions whose entries consist
    /// entirely of file objects (i.e. no subtrees).
    async fn get_all_versions(
        &self,
        owner: &str,
        repo: &str,
        path: PackagePath,
    ) -> Result<BTreeSet<PackageVersion>, GitHubError> {
        const SEPARATOR: char = '/';

        let endpoint = format!(
            "{REST_API_URL}/repos/{owner}/{repo}/git/trees/HEAD:{path}?recursive={recursive}",
            recursive = true
        );

        let response = self
            .0
            .get(endpoint)
            .header(ACCEPT, GITHUB_JSON_MIME)
            .header(X_GITHUB_API_VERSION, REST_API_VERSION)
            .send()
            .await?
            .error_for_status()?;

        let GitTree { tree, .. } = response.json::<GitTree>().await?;

        let versions = tree
            .iter()
            .filter(|entry| entry.path.matches(SEPARATOR).count() == 1)
            .chunk_by(|entry| {
                entry
                    .path
                    .split_once(SEPARATOR)
                    .map_or(entry.path.as_str(), |(version, _rest)| version)
            })
            .into_iter()
            .filter_map(|(version, mut group)| {
                group
                    .all(|object| !object.is_tree())
                    .then(|| version.parse::<PackageVersion>().ok())?
            })
            .collect::<BTreeSet<_>>();

        if versions.is_empty() {
            Err(GitHubError::NoValidFiles { path })
        } else {
            Ok(versions)
        }
    }
}

fn parse_package_identifiers(tree: &[TreeObject]) -> BTreeSet<PackageIdentifier> {
    tree.iter()
        .filter(|entry| entry.is_blob())
        .filter_map(|entry| entry.path.rsplit('/').next())
        .filter_map(|file_name| file_name.strip_suffix(".installer.yaml"))
        .filter_map(|identifier| identifier.parse::<PackageIdentifier>().ok())
        .collect::<BTreeSet<_>>()
}
