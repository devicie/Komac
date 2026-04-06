mod advapi32;
mod call;
pub mod int64op;
mod kernel32;
mod parsed_call;
mod shell32;

use std::{borrow::Cow, cell::RefCell, collections::HashMap};

use advapi32::Advapi32;
use call::Call;
pub use kernel32::Kernel32;
use parsed_call::{Destination, ParsedCall, Proc, Source};
use shell32::Shell32;

use crate::analysis::installers::nsis::state::NsisState;

/// A System call parameter with its source operand already resolved to a concrete string value.
struct ResolvedParam {
    source: Option<String>,
    destination: Option<Destination>,
}

impl ResolvedParam {
    fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    fn destination(&self) -> Option<Destination> {
        self.destination
    }
}

/// A System call with all parameter sources pre-resolved from the NSIS state.
struct ResolvedCall<'a> {
    function: &'a str,
    parameters: Vec<ResolvedParam>,
    return_destination: Destination,
}

impl ResolvedCall<'_> {
    fn function(&self) -> &str {
        self.function
    }

    fn parameters(&self) -> &[ResolvedParam] {
        &self.parameters
    }

    fn return_destination(&self) -> Destination {
        self.return_destination
    }
}

thread_local! {
    static STORED_REGISTERS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Mock Windows version data indexed by the struct pointer used in GetVersionEx.
    static MOCK_VERSION_STRUCTS: RefCell<HashMap<String, Vec<String>>> = RefCell::new(HashMap::new());
}

#[derive(Clone, Debug)]
pub struct MockCaller {
    advapi32: Advapi32,
    kernel32: Kernel32,
    shell32: Shell32,
}

impl MockCaller {
    /// Creates a new mock caller.
    #[inline]
    pub fn new() -> Self {
        Self {
            advapi32: Advapi32::new(),
            kernel32: Kernel32::new(),
            shell32: Shell32::new(),
        }
    }

    /// Returns the mock [`Kernel32`].
    #[inline]
    pub const fn kernel32(&self) -> &Kernel32 {
        &self.kernel32
    }

    /// Mocks a Windows system call.
    ///
    /// Returns `true` if logic was successfully executed for the mocked call, or `false` if the
    /// call was not in the expected format or is unimplemented.
    pub fn call(&mut self, state: &mut NsisState, call: &str) -> bool {
        let Some(parsed) = ParsedCall::parse(call) else {
            return false;
        };

        // Handle struct-pointer operations (`*ADDR(...)` and `*(...)`) directly.
        if let Proc::StructPtr(addr) = parsed.proc() {
            if parsed.return_destination() != Destination::Ignored {
                // New struct allocation: mint a pointer key from the current stack depth
                // so it is unique and stable across the alloc → GetVersionEx → read sequence.
                let key = state.stack.len().to_string();
                tracing::debug!("System: struct alloc → mock pointer {key}");
                store_call_result(state, parsed.return_destination(), &key);
            } else {
                // Struct read/write: resolve the address to find stored mock data.
                // When the address is empty (`*(...)`) the script relies on r0 holding
                // the struct pointer that was set by the preceding allocation.
                let key = if addr.is_empty() {
                    state
                        .variables
                        .get(&0usize)
                        .map(str::to_owned)
                        .unwrap_or_default()
                } else {
                    match Source::parse(addr) {
                        Some(Source::Register(idx)) => state
                            .variables
                            .get(&idx)
                            .map(str::to_owned)
                            .unwrap_or_default(),
                        Some(Source::Int(n)) => n.to_string(),
                        Some(Source::Stack) => state
                            .stack
                            .pop()
                            .map(|s| s.into_owned())
                            .unwrap_or_default(),
                        _ => addr.to_owned(),
                    }
                };
                MOCK_VERSION_STRUCTS.with(|m| {
                    if let Some(fields) = m.borrow().get(&key) {
                        for (param, value) in parsed.parameters().iter().zip(fields.iter()) {
                            if let Some(dest) = param.destination() {
                                store_call_result(state, dest, value);
                            }
                        }
                    }
                });
            }
            return true;
        }

        // For all other proc types resolve parameter sources and dispatch to module handlers.
        let resolved = ResolvedCall {
            function: parsed.function(),
            parameters: parsed
                .parameters()
                .iter()
                .map(|p| ResolvedParam {
                    source: resolve_source(state, p.source()),
                    destination: p.destination(),
                })
                .collect(),
            return_destination: parsed.return_destination(),
        };

        if parsed.module().eq_ignore_ascii_case(Advapi32::NAME) {
            return self.advapi32.call(state, &resolved);
        }

        if parsed.module().eq_ignore_ascii_case(Kernel32::NAME) {
            return self.kernel32.call(state, &resolved);
        }

        if parsed.module().eq_ignore_ascii_case(Shell32::NAME) {
            return self.shell32.call(state, &resolved);
        }

        false
    }
}

impl Default for MockCaller {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

pub(super) fn set_mock_version_struct(pointer_key: String) {
    MOCK_VERSION_STRUCTS.with(|m| {
        m.borrow_mut().insert(
            pointer_key,
            vec![
                "284".to_string(),   // dwOSVersionInfoSize
                "10".to_string(),    // dwMajorVersion
                "0".to_string(),     // dwMinorVersion
                "19041".to_string(), // dwBuildNumber
                "2".to_string(),     // dwPlatformId
                "".to_string(),      // szCSDVersion
            ],
        )
    });
}

/// Resolves a [`Source`] operand to its string value using the current NSIS state.
///
/// [`Source::Stack`] pops from the stack; [`Source::Register`] reads the register.
/// Returns `None` for [`Source::Ignored`] or a register/stack miss.
fn resolve_source(state: &mut NsisState, source: Option<Source<'_>>) -> Option<String> {
    match source? {
        Source::Str(s) => Some(s.to_owned()),
        Source::Int(n) => Some(n.to_string()),
        Source::Register(idx) => state.variables.get(&idx).map(str::to_owned),
        Source::Stack => state.stack.pop().map(|s| s.into_owned()),
        Source::Null => Some(String::new()),
        Source::Ignored => None,
    }
}

pub(super) fn store_call_result(state: &mut NsisState, destination: Destination, result: &str) {
    match destination {
        Destination::Stack => {
            state.stack.push(Cow::Owned(result.to_owned()));
        }
        Destination::Register(idx) => {
            state.variables.insert(idx, result.to_owned());
        }
        Destination::Null | Destination::Ignored => {}
    }
}

/// Emulates `System::Store` by saving/loading selected NSIS registers.
pub fn store(state: &mut NsisState) {
    let Some(args) = state.stack.pop() else {
        return;
    };

    let args = args.trim();

    if let Some(regs_str) = args.strip_prefix('S') {
        let regs = parse_register_list(regs_str);

        STORED_REGISTERS.with(|stored| {
            let mut stored = stored.borrow_mut();
            stored.clear();

            for idx in &regs {
                let value = state.variables.get(idx).unwrap_or_default();
                stored.push(value.to_string());
            }
        });
    } else if let Some(regs_str) = args.strip_prefix('L') {
        let regs = parse_register_list(regs_str);

        STORED_REGISTERS.with(|stored| {
            let stored = stored.borrow();

            for (i, idx) in regs.iter().enumerate() {
                if let Some(value) = stored.get(i) {
                    state.variables.insert(*idx, Cow::Owned(value.clone()));
                }
            }
        });
    }
}

fn parse_register_list(regs_str: &str) -> Vec<usize> {
    let regs_str = regs_str.trim();

    if regs_str.is_empty() {
        return (0..10).collect();
    }

    regs_str
        .split_whitespace()
        .filter_map(parse_register_name)
        .collect()
}

fn parse_register_name(name: &str) -> Option<usize> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }

    if name.starts_with('r') || name.starts_with('R') {
        name[1..].parse::<usize>().ok().map(|number| {
            if name.starts_with('R') && number < 10 {
                number + 10
            } else {
                number
            }
        })
    } else {
        name.parse::<usize>().ok()
    }
}
