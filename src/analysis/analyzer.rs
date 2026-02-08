use std::{collections::BTreeSet, io::Cursor, mem};

use camino::Utf8Path;
use color_eyre::eyre::{Result, bail};
use memmap2::Mmap;
use tracing::debug;
use winget_types::{
    installer::Installer,
    locale::{Copyright, PackageName, Publisher},
};
use yara_x::mods::PE;

use super::extensions::{APPX, APPX_BUNDLE, EXE, MSI, MSIX, MSIX_BUNDLE, ZIP};
use crate::{
    analysis::{
        Icon, Installers, extract_pe_icons,
        installers::{
            Exe, Msi, Zip,
            msix_family::{Msix, bundle::MsixBundle},
        },
    },
    traits::FromVSVersionInfo,
};

pub struct Analyzer<'data> {
    pub file_name: String,
    pub copyright: Option<Copyright>,
    pub package_name: Option<PackageName>,
    pub publisher: Option<Publisher>,
    pub installers: Vec<Installer>,
    pub icons: BTreeSet<Icon>,
    pub zip: Option<Zip<Cursor<&'data [u8]>>>,
}

impl<'data> Analyzer<'data> {
    pub fn new(data: &'data Mmap, file_name: &str) -> Result<Self> {
        let extension = Utf8Path::new(file_name)
            .extension()
            .unwrap_or_default()
            .to_ascii_lowercase();

        let mut zip = None;
        let mut copyright = None;
        let mut package_name = None;
        let mut publisher = None;
        let mut icons = BTreeSet::new();
        let installers = match extension.as_str() {
            MSI => {
                let msi = Msi::new(Cursor::new(data.as_ref()))?;
                icons = msi.icons();
                msi.installers()
            }
            MSIX | APPX => {
                let msix = Msix::new(Cursor::new(data.as_ref()))?;
                icons = msix.icons();
                msix.installers()
            }
            MSIX_BUNDLE | APPX_BUNDLE => MsixBundle::new(Cursor::new(data.as_ref()))?.installers(),
            ZIP => {
                let mut scoped_zip = Zip::new(Cursor::new(data.as_ref()))?;
                let installers = mem::take(&mut scoped_zip.installers);
                zip = Some(scoped_zip);
                installers
            }
            EXE => {
                let pe = yara_x::mods::invoke::<PE>(data.as_ref()).unwrap();
                debug!(?pe.version_info);
                copyright = Copyright::from_version_info(&pe.version_info);
                package_name = PackageName::from_version_info(&pe.version_info);
                publisher = Publisher::from_version_info(&pe.version_info);
                let exe = Exe::new(Cursor::new(data.as_ref()), &pe)?;
                icons = exe.icons();
                icons.extend(extract_pe_icons(&pe, data.as_ref()));
                exe.installers()
                    .into_iter()
                    .map(|mut installer| {
                        if installer.architecture.is_x86() {
                            let file_name_lower = file_name.to_lowercase();
                            if file_name_lower.contains("arm64") {
                                installer.architecture =
                                    winget_types::installer::Architecture::Arm64;
                            } else if file_name_lower.contains("x64") {
                                installer.architecture = winget_types::installer::Architecture::X64;
                            }
                        }
                        installer
                    })
                    .collect()
            }
            _ => bail!(r#"Unsupported file extension: "{extension}""#),
        };
        Ok(Self {
            installers,
            file_name: String::new(),
            copyright,
            package_name,
            publisher,
            icons,
            zip,
        })
    }
}
