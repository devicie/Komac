use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct NuSpec {
    pub metadata: Metadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub id: String,
    pub version: String,
    pub title: String,
    pub authors: String,
    pub owners: String,
    pub icon_url: String,
    pub require_license_acceptance: bool,
    pub description: String,
    pub copyright: String,
}
