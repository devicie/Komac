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
    // 0=BasicMsi, InstallScript, BasicMsiWithInstallScript, Unknown, InstallScriptUnicode
    pub script_driven: Option<String>,
    pub company_name: Option<String>,
    pub package_name: Option<String>,
    #[serde(alias = "AppName")]
    pub product: Option<String>,
    #[serde(alias = "ProductGUID")]
    pub product_code: Option<String>,
    pub product_version: Option<String>,
    pub upgrade_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Languages {
    pub default: String,
}
