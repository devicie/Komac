use winget_types::{PackageVersion, installer::NestedInstallerFiles};

use crate::{
    analysis::installers::Zip,
    github::{
        GITHUB_HOST, GitHubError,
        client::{GitHub, GitHubValues},
    },
    manifests::Url,
    traits::path::{LowercaseExtension, NormalizePath},
};

pub fn resolve_replace_version<'a>(
    replace: Option<&'a PackageVersion>,
    versions: &'a std::collections::BTreeSet<winget_types::PackageVersion>,
    latest_version: &'a PackageVersion,
    package_version: &PackageVersion,
) -> std::result::Result<Option<&'a PackageVersion>, String> {
    let replace_version = replace
        .map(|version| {
            if version.is_latest() {
                latest_version
            } else {
                version
            }
        })
        .filter(|&version| version.as_str() != package_version.as_str());

    if let Some(version) = replace_version
        && !versions.contains(version)
    {
        if let Some(closest) = version.closest(versions) {
            return Err(format!(
                "Replacement version {version} does not exist. The closest version is {closest}"
            ));
        }
        return Err(format!("Replacement version {version} does not exist"));
    }

    Ok(replace_version)
}

pub async fn fetch_github_values(
    github: &GitHub,
    urls: &[Url],
) -> std::result::Result<Option<GitHubValues>, GitHubError> {
    if let Some(url) = urls.iter().find(|url| url.host_str() == Some(GITHUB_HOST)) {
        github
            .get_all_values_from_url(url.clone().into_inner())
            .await
            .transpose()
    } else {
        Ok(None)
    }
}

pub fn fix_relative_paths<R: std::io::Read + std::io::Seek>(
    nested_installer_files: std::collections::BTreeSet<NestedInstallerFiles>,
    zip: Option<&Zip<R>>,
) -> std::collections::BTreeSet<NestedInstallerFiles> {
    let Some(zip) = zip else {
        return nested_installer_files;
    };

    nested_installer_files
        .into_iter()
        .filter_map(|nested_installer_files| {
            if zip
                .possible_installer_files
                .contains(&nested_installer_files.relative_file_path.normalize())
            {
                Some(nested_installer_files)
            } else {
                zip.possible_installer_files
                    .iter()
                    .min_by_key(|file_path| {
                        strsim::levenshtein(
                            file_path.as_str(),
                            nested_installer_files.relative_file_path.as_str(),
                        )
                    })
                    .map(|path| NestedInstallerFiles {
                        relative_file_path: path.lowercase_extension(),
                        ..nested_installer_files
                    })
            }
        })
        .collect()
}
