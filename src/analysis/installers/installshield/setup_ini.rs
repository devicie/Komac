use serde::Deserialize;

// https://docs.revenera.com/installshield28helplib/helplibrary/SetupIni.htm
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetupIni {
    pub info: Info,
    pub startup: Startup,
    pub languages: Languages,
    #[serde(rename = "ISSetupPrerequisites")]
    pub prerequisites: Option<Prerequisites>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Info {
    pub name: String,
    pub version: String,
    pub disk_space: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Startup {
    pub advertise_while_elevated: Option<String>,
    pub cmd_line: String,
    pub company_name: Option<String>,
    pub do_maintenance: String,
    pub dot_net_optional_install_if_silent: String,
    pub enable_lang_dlg: String,
    pub launcher_name: String,
    pub log_results: String,
    pub on_upgrade: String,
    pub package_code: String,
    pub package_name: String,
    pub product: String,
    pub product_code: String,
    pub product_version: String,
    pub script_driven: String,
    pub script_ver: String,
    pub suppress_reboot: Option<String>,
    #[serde(rename = "SuppressWrongOS")]
    pub suppress_wrong_os: String,
    #[serde(rename = "UI")]
    pub ui: Option<String>,
    pub upgrade_code: Option<String>,
    pub wait_installation: Option<String>,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Prerequisites {
    pub pre_req0: String,
    pub pre_req1: Option<String>,
}
