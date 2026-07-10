//! Parsing of the compiled Setup Factory setup script (`irsetup.dat`).
//!
//! The script embeds a table of the project's *session variables* - the values the author entered
//! in the Setup Factory designer, such as `%ProductName%`, `%CompanyName%` and `%ProductVer%`. Each
//! entry is a length-prefixed name (always beginning and ending with `%`) immediately followed by a
//! length-prefixed value:
//!
//! ```text
//! ..\x0d%ProductName%\x06gloCOM\x01\x00\x00\x00..\x0d%CompanyName%\x0dBicom Systems..
//! ```
//!
//! Entries are separated by a short, version-dependent run of bytes, so rather than decode that
//! separator exactly the walker locates the `%ProductName%` entry and then scans a small window
//! ahead for the next `[len]%name%` pair. This is resilient to the separator changing between
//! Setup Factory versions.

/// The name of the session variable holding the product's display name.
const PRODUCT_NAME: &str = "%ProductName%";
/// The name of the session variable holding the publisher.
const COMPANY_NAME: &str = "%CompanyName%";
/// The name of the session variable holding the product version.
const PRODUCT_VERSION: &str = "%ProductVer%";

/// The maximum number of bytes between one entry's value and the next entry's length byte.
const MAX_SEPARATOR_LEN: usize = 16;

/// The maximum number of table entries to walk before giving up (a malformed-input guard).
const MAX_ENTRIES: usize = 512;

/// Values extracted from the setup script's session variable table.
#[derive(Debug, Default)]
pub struct ScriptMetadata {
    pub display_name: Option<String>,
    pub publisher: Option<String>,
    pub display_version: Option<String>,
}

impl ScriptMetadata {
    pub fn parse(script: &[u8]) -> Self {
        let table = SessionVarTable::walk(script);

        // Skip empty values and those that are just references to other variables (e.g. a
        // `%CompanyName%` whose value is left as `%CompanyURL%`).
        let value = |name: &str| {
            table
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
                .filter(|value| !value.is_empty() && !value.contains('%'))
                .map(str::to_owned)
        };

        Self {
            display_name: value(PRODUCT_NAME),
            publisher: value(COMPANY_NAME),
            // The version variable is author-defined and is sometimes left as a bare major number
            // (e.g. gloCOM ships `%ProductVer%` = "4" while the real version lives in a custom
            // variable). Only trust it when it looks like a real dotted version.
            display_version: value(PRODUCT_VERSION).filter(|version| version.contains('.')),
        }
    }
}

struct SessionVarTable;

impl SessionVarTable {
    fn walk(script: &[u8]) -> Vec<(String, String)> {
        // Anchor the table at the `%ProductName%` entry: its `%`-delimited name is preceded by its
        // own length byte.
        let anchor = {
            let mut anchor = Vec::with_capacity(PRODUCT_NAME.len() + 1);
            anchor.push(PRODUCT_NAME.len() as u8);
            anchor.extend_from_slice(PRODUCT_NAME.as_bytes());
            anchor
        };
        let Some(mut pos) = script
            .windows(anchor.len())
            .position(|window| window == anchor)
        else {
            return Vec::new();
        };

        let mut entries = Vec::new();
        for _ in 0..MAX_ENTRIES {
            let Some((name, value, next)) = read_entry(script, pos) else {
                break;
            };
            entries.push((name, value));

            // Find the next entry's length byte within the separator window.
            let Some(offset) = (next..script.len().min(next + MAX_SEPARATOR_LEN))
                .find(|&candidate| is_entry_start(script, candidate))
            else {
                break;
            };
            pos = offset;
        }
        entries
    }
}

/// Reads a `[name_len][name][value_len][value]` entry at `pos`, returning the name, value and the
/// offset immediately after the value. Returns `None` if the bytes at `pos` are not a valid entry.
fn read_entry(script: &[u8], pos: usize) -> Option<(String, String, usize)> {
    let name_len = usize::from(*script.get(pos)?);
    let name = script.get(pos + 1..pos + 1 + name_len)?;
    if !is_variable_name(name) {
        return None;
    }

    let value_pos = pos + 1 + name_len;
    let value_len = usize::from(*script.get(value_pos)?);
    let value = script.get(value_pos + 1..value_pos + 1 + value_len)?;

    Some((
        String::from_utf8_lossy(name).into_owned(),
        String::from_utf8_lossy(value).into_owned(),
        value_pos + 1 + value_len,
    ))
}

/// Returns whether a valid `[len]%name%` pair begins at `pos`.
fn is_entry_start(script: &[u8], pos: usize) -> bool {
    let Some(&len) = script.get(pos) else {
        return false;
    };
    let len = usize::from(len);
    script
        .get(pos + 1..pos + 1 + len)
        .is_some_and(is_variable_name)
}

/// A session variable name is delimited by `%` and contains only printable ASCII.
fn is_variable_name(bytes: &[u8]) -> bool {
    bytes.len() >= 3
        && bytes.first() == Some(&b'%')
        && bytes.last() == Some(&b'%')
        && bytes.iter().all(|&byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a `[len][name][len][value]` entry as it appears in the session variable table.
    fn entry(name: &str, value: &str) -> Vec<u8> {
        let mut bytes = vec![name.len() as u8];
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(value.len() as u8);
        bytes.extend_from_slice(value.as_bytes());
        bytes
    }

    /// Builds a table from entries joined by the four-byte separator seen between real entries.
    fn table(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut bytes = b"leading noise".to_vec();
        for (index, (name, value)) in entries.iter().enumerate() {
            if index > 0 {
                bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
            }
            bytes.extend(entry(name, value));
        }
        bytes
    }

    #[test]
    fn extracts_name_publisher_and_dotted_version() {
        let script = table(&[
            ("%ProductName%", "Locklizard Safeguard - PDF Writer"),
            ("%CompanyName%", "Locklizard Ltd."),
            ("%ProductVer%", "4.0.24"),
        ]);

        let metadata = ScriptMetadata::parse(&script);

        assert_eq!(
            metadata.display_name.as_deref(),
            Some("Locklizard Safeguard - PDF Writer")
        );
        assert_eq!(metadata.publisher.as_deref(), Some("Locklizard Ltd."));
        assert_eq!(metadata.display_version.as_deref(), Some("4.0.24"));
    }

    #[test]
    fn ignores_bare_major_version() {
        // gloCOM leaves `%ProductVer%` as a bare "4"; the real version lives elsewhere.
        let script = table(&[
            ("%ProductName%", "gloCOM"),
            ("%CompanyName%", "Bicom Systems"),
            ("%ProductVer%", "4"),
        ]);

        let metadata = ScriptMetadata::parse(&script);

        assert_eq!(metadata.display_name.as_deref(), Some("gloCOM"));
        assert_eq!(metadata.publisher.as_deref(), Some("Bicom Systems"));
        assert_eq!(metadata.display_version, None);
    }

    #[test]
    fn skips_empty_and_placeholder_values() {
        let script = table(&[
            ("%ProductName%", "Communicator"),
            ("%CompanyName%", ""),
            ("%ProductVer%", "%CustomVersion%"),
        ]);

        let metadata = ScriptMetadata::parse(&script);

        assert_eq!(metadata.display_name.as_deref(), Some("Communicator"));
        assert_eq!(metadata.publisher, None);
        assert_eq!(metadata.display_version, None);
    }

    #[test]
    fn returns_default_without_product_name() {
        let metadata = ScriptMetadata::parse(b"no session variable table here");

        assert!(metadata.display_name.is_none());
        assert!(metadata.publisher.is_none());
        assert!(metadata.display_version.is_none());
    }
}
