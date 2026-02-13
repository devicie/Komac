use serde::Deserialize;

// https://docs.revenera.com/installshield28helplib/helplibrary/SetupIni.htm
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetupIni {
    pub startup: Startup,
    pub languages: Languages,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Startup {
    pub cmd_line: String,
    #[serde(default)]
    pub script_driven: InstallType,
    pub company_name: Option<String>,
    pub package_name: Option<String>,
    #[serde(alias = "AppName")]
    pub product: String,
    #[serde(alias = "ProductGUID")]
    pub product_code: Option<String>,
    pub product_version: Option<String>,
    pub upgrade_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Languages {
    #[serde(default)]
    pub require_exact_lang_match: String,
    #[serde(default, rename = "RTLLangs")]
    pub rtl_langs: String,
    pub default: String,
    #[serde(default)]
    pub supported: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub enum InstallType {
    BasicMsi,
    #[default]
    InstallScript,
    BasicMsiWithInstallScript,
    Unknown,
    InstallScriptUnicode,
}
