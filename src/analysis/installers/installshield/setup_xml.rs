use std::collections::HashMap;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SetupXml {
    #[serde(rename = "@SuiteId")]
    pub suite_id: String,
    #[serde(rename = "ARPInfo")]
    pub arp_info: ArpInfo,
    pub language_selection: LanguageSelection,
    pub languages: Languages,
    pub set_property: Vec<SetProperty>,
}

impl SetupXml {
    pub fn get_property(&self, name: &str) -> Option<String> {
        self.set_property
            .iter()
            .find(|p| p.name == name)
            .and_then(|p| p.value.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ArpInfo {
    pub version: String,
    pub publisher: String,
    pub display_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct LanguageSelection {
    #[serde(rename = "@Default")]
    pub default: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Languages {
    #[serde(rename = "Language")]
    pub language: Vec<Language>,
}

/// Custom deserializer because `#[serde(flatten)]` can't be used with `#[serde(rename = "$value")]`
/// https://github.com/tafia/quick-xml/issues/326
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Language {
    #[serde(rename = "@lcid")]
    pub lcid: String,
    #[serde(flatten, deserialize_with = "deserialize_language_strings")]
    pub strings: HashMap<String, String>,
}

#[derive(Deserialize)]
struct LanguageString {
    #[serde(rename = "$text", default)]
    text: String,
}

fn deserialize_language_strings<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = HashMap<String, String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("language strings")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = HashMap::new();
            while let Some(key) = map.next_key::<String>()? {
                result.insert(key, map.next_value::<LanguageString>()?.text);
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(V)
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SetProperty {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Value")]
    pub value: Option<String>,
}
