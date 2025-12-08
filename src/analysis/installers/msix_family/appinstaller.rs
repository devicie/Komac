use color_eyre::eyre::{Result, bail};
use quick_xml::{Reader, events::Event};

/// Parses an `.appinstaller` file and extracts the installer URL
/// 
/// According to the App Installer file schema:
/// https://learn.microsoft.com/en-us/uwp/schemas/appinstallerschema/schema-root
/// 
/// The file contains either:
/// - MainBundle with a Uri attribute (for .msixbundle/.appxbundle)
/// - MainPackage with a Uri attribute (for .msix/.appx)
pub fn parse_appinstaller(xml_content: &str) -> Result<String> {
    let mut reader = Reader::from_str(xml_content);
    let config = reader.config_mut();
    config.expand_empty_elements = true;
    config.trim_text(true);

    loop {
        match reader.read_event()? {
            Event::Start(event) | Event::Empty(event) => {
                match event.local_name().as_ref() {
                    b"MainBundle" | b"MainPackage" => {
                        for attribute in event.attributes().flatten() {
                            if attribute.key.as_ref() == b"Uri" {
                                let uri = String::from_utf8_lossy(&attribute.value).into_owned();
                                if !uri.is_empty() {
                                    return Ok(uri);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    bail!("No MainBundle or MainPackage Uri found in .appinstaller file")
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_parse_appinstaller_with_main_bundle() {
        let xml = indoc! {r#"
            <?xml version="1.0" encoding="utf-8"?>
            <AppInstaller xmlns="http://schemas.microsoft.com/appx/appinstaller/2018" Version="2.0.5.0" Uri="https://github.com/MicaForEveryone/MicaForEveryone/releases/download/2.0.5.0/MicaForEveryone.appinstaller">
                <MainBundle Name="MicaForEveryone" Publisher="CN=Steve" Version="2.0.5.0" Uri="https://github.com/MicaForEveryone/MicaForEveryone/releases/download/2.0.5.0/MicaForEveryone_2.0.5.0_x64.msixbundle"/>
            </AppInstaller>
        "#};

        let result = parse_appinstaller(xml).unwrap();
        assert_eq!(
            result,
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

        let result = parse_appinstaller(xml).unwrap();
        assert_eq!(result, "https://example.com/TestApp_1.0.0.0_x64.msix");
    }

    #[test]
    fn test_parse_appinstaller_no_uri() {
        let xml = indoc! {r#"
            <?xml version="1.0" encoding="utf-8"?>
            <AppInstaller xmlns="http://schemas.microsoft.com/appx/appinstaller/2018" Version="1.0.0.0">
            </AppInstaller>
        "#};

        let result = parse_appinstaller(xml);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No MainBundle or MainPackage Uri found"));
    }
}
