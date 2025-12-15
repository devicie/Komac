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
    pub company_name: Option<String>,
    pub package_code: Option<String>,
    pub package_name: Option<String>,
    pub product: String,
    pub product_code: Option<String>,
    #[serde(rename = "ProductGUID")]
    pub product_guid: Option<String>,
    pub product_version: Option<String>,
    pub upgrade_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Languages {
    pub require_exact_lang_match: String,
    #[serde(rename = "RTLLangs")]
    pub rtl_langs: String,
    pub default: String,
    pub supported: String,
}
