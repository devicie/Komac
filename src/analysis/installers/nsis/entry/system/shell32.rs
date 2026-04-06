use super::{Call, ResolvedCall, store_call_result};
use crate::analysis::installers::nsis::state::NsisState;

/// A mock `Shell32` module.
#[derive(Clone, Debug, Default)]
pub struct Shell32;

impl Shell32 {
    pub const NAME: &str = "Shell32";

    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl Call for Shell32 {
    fn call(&mut self, state: &mut NsisState, call: &ResolvedCall<'_>) -> bool {
        let result = match call.function() {
            "SHChangeNotify" => "0",
            function => {
                tracing::debug!("System::Call: unhandled shell32::{function}");
                "0"
            }
        };

        store_call_result(state, call.return_destination(), result);
        true
    }
}
