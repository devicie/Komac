use color_eyre::eyre::Result;
use quick_xml::de::from_str;
use reqwest::Client;
use serde::Deserialize;
use tracing::warn;

use crate::analysis::extensions::APPINSTALLER;

/// Resolves `.appinstaller` URLs to the actual installer URL
/// 
/// If the URL ends with `.appinstaller`, this function will:
/// 1. Download the .appinstaller file
/// 2. Parse it as XML to extract the MainBundle or MainPackage Uri
/// 3. Return the extracted installer URL
pub async fn resolve_appinstaller_url(
    client: &Client,
    url: &url::Url,
) -> Result<Option<url::Url>, reqwest::Error> {
    // Check if this is an .appinstaller URL
    if !url.path().ends_with(&format!(".{APPINSTALLER}")) {
        return Ok(None);
    }

    // Download the .appinstaller file
    let response = client.get(url.clone()).send().await?;

    if let Err(err) = response.error_for_status_ref() {
        return Err(err.into());
    }

    let content = response.text().await?;

    // Parse the XML and extract the installer URL
    match from_str::<AppInstaller>(&content) {
        Ok(app_installer) => {
            if let Some(installer_url) = app_installer.get_installer_url() {
                match installer_url.parse() {
                    Ok(new_url) => Ok(Some(new_url)),
                    Err(e) => {
                        warn!(
                            "Failed to parse extracted installer URL from .appinstaller: {}",
                            e
                        );
                        Ok(None)
                    }
                }
            } else {
                warn!("No MainBundle or MainPackage Uri found in .appinstaller file");
                Ok(None)
            }
        }
        Err(e) => {
            warn!("Failed to parse .appinstaller file: {}", e);
            Ok(None)
        }
    }
}

/// <https://learn.microsoft.com/en-us/uwp/schemas/appinstallerschema/element-appinstaller>
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AppInstaller {
    #[serde(rename = "MainBundle", default)]
    main_bundle: Option<MainBundle>,
    #[serde(rename = "MainPackage", default)]
    main_package: Option<MainPackage>,
}

impl AppInstaller {
    fn get_installer_url(&self) -> Option<String> {
        self.main_bundle
            .as_ref()
            .map(|bundle| bundle.uri.clone())
            .or_else(|| self.main_package.as_ref().map(|package| package.uri.clone()))
    }
}

/// <https://learn.microsoft.com/en-us/uwp/schemas/appinstallerschema/element-main-bundle>
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MainBundle {
    #[serde(rename = "@Uri")]
    uri: String,
}

/// <https://learn.microsoft.com/en-us/uwp/schemas/appinstallerschema/element-main-package>
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MainPackage {
    #[serde(rename = "@Uri")]
    uri: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[tokio::test]
    async fn test_resolve_real_appinstaller_url() {
        // Use the real URL from the issue
        let url = "https://github.com/MicaForEveryone/MicaForEveryone/releases/download/2.0.5.0/MicaForEveryone.appinstaller"
            .parse()
            .unwrap();
        
        let client = Client::new();
        let result = resolve_appinstaller_url(&client, &url).await;
        
        // The function should succeed and return a URL
        assert!(result.is_ok());
        let resolved_url = result.unwrap();
        assert!(resolved_url.is_some());
        
        // The resolved URL should be a .msixbundle file
        let final_url = resolved_url.unwrap();
        assert!(final_url.path().ends_with(".msixbundle"));
    }

    #[test]
    fn test_parse_appinstaller_with_main_bundle() {
        let xml = indoc! {r#"
            <?xml version="1.0" encoding="utf-8"?>
            <AppInstaller xmlns="http://schemas.microsoft.com/appx/appinstaller/2018" Version="2.0.5.0" Uri="https://github.com/MicaForEveryone/MicaForEveryone/releases/download/2.0.5.0/MicaForEveryone.appinstaller">
                <MainBundle Name="MicaForEveryone" Publisher="CN=Steve" Version="2.0.5.0" Uri="https://github.com/MicaForEveryone/MicaForEveryone/releases/download/2.0.5.0/MicaForEveryone_2.0.5.0_x64.msixbundle"/>
            </AppInstaller>
        "#};

        let app_installer: AppInstaller = from_str(xml).unwrap();
        let url = app_installer.get_installer_url().unwrap();
        assert_eq!(
            url,
            "https://github.com/MicaForEveryone/MicaForEveryone/releases/download/2.0.5.0/MicaForEveryone_2.0.5.0_x64.msixbundle"
        );
    }

    #[test]
    fn test_parse_appinstaller_with_main_package() {
        let xml = indoc! {r#"
            <?xml version="1.0" encoding="utf-8"?>
            <AppInstaller xmlns="http://schemas.microsoft.com/appx/appinstaller/2018" Version="1.0.0.0" Uri="https://example.com/app.appinstaller">
                <MainPackage Name="TestApp" Publisher="CN=TestPublisher" Version="1.0.0.0" Uri="https://example.com/TestApp_1.0.0.0_x64.msix"/>
            </AppInstaller>
        "#};

        let app_installer: AppInstaller = from_str(xml).unwrap();
        let url = app_installer.get_installer_url().unwrap();
        assert_eq!(url, "https://example.com/TestApp_1.0.0.0_x64.msix");
    }

    #[test]
    fn test_parse_appinstaller_no_uri() {
        let xml = indoc! {r#"
            <?xml version="1.0" encoding="utf-8"?>
            <AppInstaller xmlns="http://schemas.microsoft.com/appx/appinstaller/2018" Version="1.0.0.0">
            </AppInstaller>
        "#};

        let app_installer: AppInstaller = from_str(xml).unwrap();
        let url = app_installer.get_installer_url();
        assert!(url.is_none());
    }
}
