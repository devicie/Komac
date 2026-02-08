use std::collections::{BTreeSet, HashMap};

use base64ct::{Base64, Encoding};
use url::Url;
use winget_types::locale::Icon;
use yara_x::mods::{PE, pe::ResourceType};

fn icon_from_data(data: &[u8], mime: &str) -> Option<Icon> {
    let url = Url::parse(&format!(
        "data:{mime};base64,{}",
        Base64::encode_string(data)
    ))
    .ok()?;
    serde_json::from_value(serde_json::json!({
        "IconUrl": url.as_str(),
        "IconFileType": "ico"
    }))
    .ok()
}

pub fn create_icon(data: Vec<u8>, path: &str) -> Option<Icon> {
    let mime = match path.rsplit('.').next()?.to_ascii_lowercase().as_str() {
        "ico" => "image/x-icon",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        _ => return None,
    };
    icon_from_data(&data, mime)
}

pub fn extract_pe_icons(pe: &PE, data: &[u8]) -> BTreeSet<Icon> {
    let icon_resources: HashMap<u32, &[u8]> = pe
        .resources
        .iter()
        .filter(|resource| {
            resource.type_() == ResourceType::RESOURCE_TYPE_ICON && resource.offset() != 0
        })
        .filter_map(|resource| {
            let start = resource.offset() as usize;
            let end = start + resource.length() as usize;
            data.get(start..end).map(|bytes| (resource.id(), bytes))
        })
        .collect();

    pe.resources
        .iter()
        .filter(|resource| {
            resource.type_() == ResourceType::RESOURCE_TYPE_GROUP_ICON && resource.offset() != 0
        })
        .filter_map(|resource| {
            let start = resource.offset() as usize;
            let end = start + resource.length() as usize;
            let group = data.get(start..end)?;
            let icon_count = u16::from_le_bytes(group.get(4..6)?.try_into().ok()?) as usize;

            let entries: Vec<_> = (0..icon_count)
                .filter_map(|i| {
                    let entry = group.get(6 + i * 14..6 + i * 14 + 14)?;
                    let id = u16::from_le_bytes([entry[12], entry[13]]) as u32;
                    icon_resources.get(&id).map(|icon_data| (entry, *icon_data))
                })
                .collect();

            if entries.is_empty() {
                return None;
            }

            let total_size = 6
                + entries.len() * 16
                + entries
                    .iter()
                    .map(|(_, icon_data)| icon_data.len())
                    .sum::<usize>();
            let mut ico_file = Vec::with_capacity(total_size);
            ico_file.extend_from_slice(&group[0..4]);
            ico_file.extend_from_slice(&(entries.len() as u16).to_le_bytes());

            let mut data_offset = 6 + entries.len() * 16;
            for (entry, icon_data) in &entries {
                ico_file.extend_from_slice(&[entry[0], entry[1], entry[2], 0]);
                ico_file.extend_from_slice(&entry[4..8]);
                ico_file.extend_from_slice(&(icon_data.len() as u32).to_le_bytes());
                ico_file.extend_from_slice(&(data_offset as u32).to_le_bytes());
                data_offset += icon_data.len();
            }
            for (_, icon_data) in &entries {
                ico_file.extend_from_slice(icon_data);
            }

            icon_from_data(&ico_file, "image/x-icon")
        })
        .collect()
}
