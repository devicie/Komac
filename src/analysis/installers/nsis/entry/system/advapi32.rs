use super::{Call, ResolvedCall, store_call_result};
use crate::analysis::installers::nsis::state::NsisState;

/// A mock [`Advapi32`] module.
#[derive(Clone, Debug, Default)]
pub struct Advapi32;

impl Advapi32 {
    pub const NAME: &str = "Advapi32";
    /// Creates a new mock [`Advapi32`].
    #[inline]
    pub fn new() -> Self {
        Self
    }
}

impl Call for Advapi32 {
    fn call(&mut self, state: &mut NsisState, call: &ResolvedCall<'_>) -> bool {
        let result = match call.function() {
            "OpenSCManager" | "OpenService" => "1",
            "QueryServiceStatus" | "CloseServiceHandle" => "1",
            function => {
                tracing::debug!("System::Call: unhandled advapi32::{function}");
                "0"
            }
        };

        store_call_result(state, call.return_destination(), result);
        true
    }
}
