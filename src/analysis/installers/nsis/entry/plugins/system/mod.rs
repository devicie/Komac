pub mod call;
pub mod int64op;

use std::borrow::Cow;

use crate::analysis::installers::nsis::state::NsisState;
use tracing::{debug, warn};

thread_local! {
    static STORED_REGISTERS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// https://nsis.sourceforge.io/System.html
pub fn evaluate(state: &mut NsisState, function_str: &str) {
    match function_str {
        "Call" => {
            if let Some(args) = state.stack.pop() {
                call::evaluate(state, &args);
            }
        }
        "Free" => {
            if let Some(address) = state.stack.pop() {
                debug!("System: Freed address {}", address);
            }
        }
        "Int64Op" => {
            let result = int64op::evaluate(state);
            state.stack.push(result.into());
        }
        "Store" => {
            // Format: S [reg]... to save, L [reg]... to load
            // If no registers specified, save/load $0-$9 (r0-r9)
            if let Some(args) = state.stack.pop() {
                let args = args.trim();
                if let Some(regs_str) = args.strip_prefix('S') {
                    let regs_str = regs_str.trim();
                    let regs: Vec<usize> = if regs_str.is_empty() {
                        (0..10).collect()
                    } else {
                        regs_str
                            .split_whitespace()
                            .filter_map(parse_register_name)
                            .collect()
                    };

                    STORED_REGISTERS.with(|stored| {
                        let mut stored = stored.borrow_mut();
                        stored.clear();
                        for idx in &regs {
                            let val = state.variables.get(idx).unwrap_or("");
                            debug!("System::Store S: saving r{} = '{}'", idx, val);
                            stored.push(val.to_string());
                        }
                    });
                } else if let Some(regs_str) = args.strip_prefix('L') {
                    let regs_str = regs_str.trim();
                    let regs: Vec<usize> = if regs_str.is_empty() {
                        (0..10).collect()
                    } else {
                        regs_str
                            .split_whitespace()
                            .filter_map(parse_register_name)
                            .collect()
                    };

                    STORED_REGISTERS.with(|stored| {
                        let stored = stored.borrow();
                        for (i, idx) in regs.iter().enumerate() {
                            if let Some(val) = stored.get(i) {
                                debug!("System::Store L: loading r{} = '{}'", idx, val);
                                state.variables.insert(*idx, Cow::Owned(val.clone()));
                            }
                        }
                    });
                }
            }
        }
        _ => {
            // Alloc, StrAlloc, Copy, Get
            warn!("System: unimplemented function {}", function_str);
        }
    }
}

fn parse_register_name(name: &str) -> Option<usize> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }

    // Handle r0-r9 -> 0-9, R0-R9 or r10-r19 -> 10-19
    if name.starts_with('r') || name.starts_with('R') {
        name[1..].parse::<usize>().ok().map(|n| {
            if name.starts_with('R') && n < 10 {
                n + 10
            } else {
                n
            }
        })
    } else {
        // Just a number
        name.parse::<usize>().ok()
    }
}
