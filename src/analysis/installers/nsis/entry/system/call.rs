use tracing::debug;

use crate::analysis::installers::nsis::state::NsisState;

pub fn evaluate(state: &mut NsisState, api_call: &str) {
    // Parse the return specification (e.g., "i.r3", "l .s", etc.)
    // Return spec format: return_type.destination or return_type destination
    // return_type: i (int), l (long), p (pointer), v (void), etc.
    // destination: s (stack), r0-r9 (variables), R0-R9 (registers), n (null/none)

    debug!("System: calling {}", api_call);

    // Find the closing parenthesis of the function call
    let closing_paren = api_call.rfind(')');
    let return_spec = if let Some(pos) = closing_paren {
        &api_call[pos + 1..]
    } else {
        ""
    };

    // Parse return type and destination
    // Examples: "i.r3", "l .s", "i.R6", " i.r2"
    let return_spec = return_spec.trim();
    let has_return_spec = return_spec.len() > 0
        && (return_spec.starts_with(|c: char| c.is_alphabetic()) || return_spec.starts_with('.'));

    // Determine mock result based on API function
    let result = if api_call.contains("kernel32::") {
        if api_call.contains("GetTickCount") {
            "0" // Mock tick count
        } else if api_call.contains("GetLocalTime") || api_call.contains("GetSystemTime") {
            "0" // Success
        } else if api_call.contains("GetVersionEx") {
            "0" // Success (indicating API success)
        } else if api_call.contains("GetCurrentProcess") {
            "-1" // Mock process handle
        } else if api_call.contains("IsWow64Process") {
            "0" // Not WOW64
        } else {
            debug!("System: unhandled kernel32 function {}", api_call);
            "0"
        }
    } else if api_call.contains("advapi32::") {
        if api_call.contains("OpenSCManager") {
            "1" // Mock handle
        } else if api_call.contains("OpenService") {
            "1" // Mock handle
        } else if api_call.contains("QueryServiceStatus") {
            "1" // Success
        } else if api_call.contains("CloseServiceHandle") {
            "1" // Success
        } else {
            debug!("System: unhandled advapi32 function {}", api_call);
            "0"
        }
    } else if api_call.contains("shell32::") {
        if api_call.contains("SHChangeNotify") {
            "0" // Success
        } else {
            debug!("System: unhandled shell32 function {}", api_call);
            "0"
        }
    } else if api_call.starts_with('*') && api_call.contains('(') {
        // Handle struct allocations and calls (like "*(&i2,&i2...)")
        "0" // Mock memory/struct operation
    } else {
        debug!("System: unhandled function {}", api_call);
        "0"
    };

    // Store result in the appropriate location if return spec exists
    if has_return_spec {
        // Parse the destination from return spec
        // Format can be: "i.r3", "l .s", " i.R6", etc.
        let spec_parts: Vec<&str> = return_spec
            .split(|c: char| c == '.' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .collect();

        if spec_parts.len() >= 2 {
            let destination = spec_parts[1];

            // Store result based on destination
            if destination == "s" {
                // Push to stack
                state.stack.push(result.into());
            } else if destination.starts_with('r') || destination.starts_with('R') {
                // Store in register/variable
                // For simulation purposes, we can store in variables
                // r0-r9 are variables $0-$9, R0-R9 are registers $R0-$R9
                if let Some(reg_num) = destination.chars().skip(1).next() {
                    if let Some(digit) = reg_num.to_digit(10) {
                        let var_index = if destination.starts_with('R') {
                            // $R0-$R9 are variables 10-19
                            (digit + 10) as usize
                        } else {
                            // $0-$9 are variables 0-9
                            digit as usize
                        };

                        state.variables.insert(var_index, result);
                    }
                }
            }
            // destination "n" means no output, ignore
        } else if spec_parts.len() == 1 {
            // Only return type specified, no explicit destination - ignore result
        }
    }
    // No return spec means result is discarded
}
