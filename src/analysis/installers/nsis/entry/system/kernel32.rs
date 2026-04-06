use std::borrow::Borrow;

use indexmap::IndexMap;
use tracing::debug;

use super::{Call, ResolvedCall, set_mock_version_struct, store_call_result};
use crate::analysis::installers::nsis::state::NsisState;

/// A mock [`Kernel32`] module.
#[derive(Clone, Debug)]
pub struct Kernel32 {
    environment_variables: IndexMap<String, String>,
}

impl Kernel32 {
    pub const NAME: &str = "Kernel32";

    /// Creates a new mock [`Kernel32`].
    #[inline]
    pub fn new() -> Self {
        Self {
            environment_variables: IndexMap::new(),
        }
    }

    /// Returns a map of environment variables created with [`Kernel32::SetEnvironmentVariable`].
    ///
    /// [`Kernel32::SetEnvironmentVariable`]: Self::set_environment_variable
    #[inline]
    pub const fn environment_variables(&self) -> &IndexMap<String, String> {
        &self.environment_variables
    }

    /// Sets an internal environment variable, mocking [`SetEnvironmentVariable`].
    ///
    /// If `value` is `None`, the environment variable is removed.
    ///
    /// [`SetEnvironmentVariable`]: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-setenvironmentvariable
    fn set_environment_variable<N, V>(&mut self, name: N, value: Option<V>)
    where
        N: Into<String> + Borrow<str>,
        V: Into<String>,
    {
        if let Some(value) = value {
            self.environment_variables.insert(name.into(), value.into());
        } else {
            self.environment_variables.swap_remove(name.borrow());
        }
    }
}

impl Call for Kernel32 {
    fn call(&mut self, state: &mut NsisState, call: &ResolvedCall<'_>) -> bool {
        match call.function() {
            "SetEnvironmentVariable" => {
                let params = call.parameters();
                let name = params.first().and_then(|p| p.source()).map(str::to_owned);
                if let Some(name) = name {
                    let value = params.get(1).and_then(|p| p.source()).map(str::to_owned);
                    self.set_environment_variable(name, value);
                }
                store_call_result(state, call.return_destination(), "1");
                true
            }
            "GetVersionEx" => {
                if let Some(key) = call
                    .parameters()
                    .first()
                    .and_then(|p| p.source())
                    .map(str::to_owned)
                {
                    set_mock_version_struct(key);
                }
                store_call_result(state, call.return_destination(), "1");
                true
            }
            "IsWow64Process" => {
                // Write FALSE (not running under WOW64) to the out-pointer destination.
                if let Some(dest) = call.parameters().get(1).and_then(|p| p.destination()) {
                    store_call_result(state, dest, "0");
                }
                store_call_result(state, call.return_destination(), "1");
                true
            }
            "IsWow64Process2" => {
                // pProcessMachine → IMAGE_FILE_MACHINE_UNKNOWN (0x0000).
                if let Some(dest) = call.parameters().get(1).and_then(|p| p.destination()) {
                    store_call_result(state, dest, "0");
                }
                // pNativeMachine → IMAGE_FILE_MACHINE_ARM64 (0xAA64 = 43620).
                if let Some(dest) = call.parameters().get(2).and_then(|p| p.destination()) {
                    store_call_result(state, dest, "43620");
                }
                store_call_result(state, call.return_destination(), "1");
                true
            }
            "GetTickCount" => {
                store_call_result(state, call.return_destination(), "0");
                true
            }
            "GetLocalTime" | "GetSystemTime" => {
                store_call_result(state, call.return_destination(), "0");
                true
            }
            "GetCurrentProcess" => {
                store_call_result(state, call.return_destination(), "-1");
                true
            }
            function => {
                debug!("System::Call: unhandled kernel32::{function}");
                store_call_result(state, call.return_destination(), "0");
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use indexmap::indexmap;

    use super::Kernel32;

    #[test]
    fn set_environment_variable() {
        let mut kernel32 = Kernel32::new();

        // Insert an environment variable
        kernel32.set_environment_variable("foobar", Some("baz"));

        assert_eq!(
            kernel32.environment_variables(),
            &indexmap! { String::from("foobar") => String::from("baz") }
        );

        // Remove an environment variable
        kernel32.set_environment_variable("foobar", None::<&str>);

        assert!(kernel32.environment_variables().is_empty());
    }
}
