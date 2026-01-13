mod call;
pub mod int64op;
mod kernel32;
mod parsed_call;

use std::{borrow::Cow, cell::RefCell};

use call::Call;
pub use kernel32::Kernel32;
use parsed_call::ParsedCall;

use crate::analysis::installers::nsis::state::NsisState;

thread_local! {
    static STORED_REGISTERS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Debug)]
pub struct MockCaller {
    kernel32: Kernel32,
}

impl MockCaller {
    /// Creates a new mock caller.
    #[inline]
    pub fn new() -> Self {
        Self {
            kernel32: Kernel32::new(),
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
    pub fn call(&mut self, call: &str) -> bool {
        let Some(parsed_call) = ParsedCall::parse(call) else {
            return false;
        };

        if parsed_call.module().eq_ignore_ascii_case(Kernel32::NAME) {
            return self.kernel32.call(&parsed_call);
        }

        false
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
