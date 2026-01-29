pub mod burn;
mod exe;
pub mod inno;
mod msi;
pub mod msix_family;
pub mod nsis;
mod qt;
pub mod utils;
mod zip;

pub use burn::Burn;
pub use exe::Exe;
pub use msi::Msi;
pub use nsis::Nsis;
pub use qt::Qt;
pub use zip::Zip;
