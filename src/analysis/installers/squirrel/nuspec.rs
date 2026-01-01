use serde::Deserialize;

// https://learn.microsoft.com/en-us/nuget/reference/nuspec
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct NuSpec {
    pub metadata: Metadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub id: String,
    pub version: String,
    pub description: String,
    pub authors: String,

    // Optional in nuspec, required in Squirrel/Velopack
    pub title: String,

    // Velopack
    pub main_exe: Option<String>,
}
