pub mod call;
pub mod int64op;

use crate::analysis::installers::nsis::state::NsisState;
use tracing::{debug, warn};

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
        _ => {
            // Alloc, StrAlloc, Copy, Store, Get
            warn!("System: unimplemented function {}", function_str);
        }
    }
}
