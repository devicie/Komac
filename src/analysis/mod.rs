mod analyzer;
mod extensions;
mod icons;
pub mod installers;
mod r#trait;

pub use analyzer::Analyzer;
pub use icons::{create_icon, extract_pe_icons};
pub use r#trait::Installers;
pub use winget_types::locale::Icon;
