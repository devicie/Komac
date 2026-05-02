mod hyperlink;

use std::sync::OnceLock;

pub use hyperlink::{Hyperlinkable, SUPPORTS_HYPERLINKS};
use indicatif::MultiProgress;

static MULTI_PROGRESS: OnceLock<MultiProgress> = OnceLock::new();

/// Returns the global [`MultiProgress`] used for download progress bars.
///
/// Callers that show interactive terminal UI should call [`MultiProgress::suspend`] on this to
/// prevent the progress bars from overwriting the prompt.
pub fn multi_progress() -> &'static MultiProgress {
    MULTI_PROGRESS.get_or_init(MultiProgress::new)
}
