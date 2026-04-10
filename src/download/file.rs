use std::fs::File;
use std::io::Read;

use camino::Utf8Path;
use chrono::NaiveDate;
use color_eyre::eyre::Result;
use sha2::{Digest, Sha256};
use winget_types::Sha256String;

use crate::manifests::Url;

pub struct DownloadedFile {
    pub file: File,
    pub url: Url,
    pub sha_256: Sha256String,
    pub file_name: String,
    pub last_modified: Option<NaiveDate>,
}

impl DownloadedFile {
    pub fn from_local(path: &Utf8Path, url: Url) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let sha_256 = Sha256String::from_digest(&Sha256::digest(&buf));
        let file_name = path.file_name().unwrap_or_else(|| path.as_str()).to_owned();
        Ok(Self {
            file,
            url,
            sha_256,
            file_name,
            last_modified: None,
        })
    }
}
