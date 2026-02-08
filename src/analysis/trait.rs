use std::collections::BTreeSet;

use winget_types::installer::Installer;
use winget_types::locale::Icon;

pub trait Installers {
    fn installers(&self) -> Vec<Installer>;

    fn icons(&self) -> BTreeSet<Icon> {
        BTreeSet::new()
    }
}
