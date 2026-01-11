use std::collections::HashMap;

use tracing::debug;

use crate::analysis::installers::nsis::state::NsisState;

thread_local! {
    static MOCK_STRUCTS: std::cell::RefCell<HashMap<String, Vec<String>>> = std::cell::RefCell::new(HashMap::new());
}

pub fn evaluate(state: &mut NsisState, api_call: &str) {
    debug!("System: calling {}", api_call);

    if api_call.starts_with('*') && api_call.contains('(') {
        handle_struct_operation(state, api_call);
        return;
    }

    let (dll, rest) = if let Some(pos) = api_call.find("::") {
        (&api_call[..pos], &api_call[pos + 2..])
    } else {
        ("", api_call)
    };

    let (function, params_and_return) = if let Some(pos) = rest.find('(') {
        (&rest[..pos], &rest[pos..])
    } else {
        (rest, "")
    };

    let return_spec = if let Some(_) = params_and_return.find('(') {
        if let Some(end) = params_and_return.rfind(')') {
            &params_and_return[end + 1..]
        } else {
            ""
        }
    } else {
        ""
    };

    let result = match dll {
        "advapi32" => match function {
            "OpenSCManager" | "OpenService" => "1",
            "QueryServiceStatus" | "CloseServiceHandle" => "1",
            _ => {
                debug!("System: unhandled advapi32 function {}", function);
                "0"
            }
        },
        "kernel32" => match function {
            "GetVersionEx" => {
                if let Some(ptr_addr) = get_param_register_value(state, params_and_return) {
                    debug!(
                        "GetVersionEx: marking struct at {} with version data",
                        ptr_addr
                    );
                    MOCK_STRUCTS.with(|structs| {
                        structs.borrow_mut().insert(
                            ptr_addr,
                            vec![
                                "284".to_string(),   // dwOSVersionInfoSize
                                "10".to_string(),    // dwMajorVersion
                                "0".to_string(),     // dwMinorVersion
                                "19041".to_string(), // dwBuildNumber
                                "2".to_string(),     // dwPlatformId
                                "".to_string(),      // szCSDVersion (128 chars)
                            ],
                        );
                    });
                }
                "1"
            }
            "IsWow64Process" | "IsWow64Process2" => {
                if function == "IsWow64Process2" {
                    debug!("{}: mocking native x64", function);
                    let output_count = params_and_return.matches("s").count();
                    if output_count >= 1 {
                        state.stack.push("0".into()); // IMAGE_FILE_MACHINE_UNKNOWN (not WOW64)
                    }
                    if output_count >= 2 {
                        // state.stack.push("34404".into()); // IMAGE_FILE_MACHINE_AMD64
                        state.stack.push("43620".into()); // IMAGE_FILE_MACHINE_ARM64
                    }
                } else if params_and_return.contains("*i") {
                    debug!("{}: mocking WOW64=FALSE (native 64-bit)", function);
                    state.stack.push("0".into());
                }
                "1"
            }
            "GetTickCount" => "0",
            "GetLocalTime" | "GetSystemTime" => "0",
            "GetCurrentProcess" => "-1",
            _ => {
                debug!("System: unhandled kernel32 function {}", function);
                "0"
            }
        },
        "shell32" => match function {
            "SHChangeNotify" => "0",
            _ => {
                debug!("System: unhandled shell32 function {}", function);
                "0"
            }
        },
        _ => {
            debug!("System: unhandled function {}", api_call);
            "0"
        }
    };

    store_result(state, return_spec, result);
}

fn get_param_register_value(state: &NsisState, params_and_return: &str) -> Option<String> {
    let params = if let Some(start) = params_and_return.find('(') {
        if let Some(end) = params_and_return.find(')') {
            &params_and_return[start + 1..end]
        } else {
            return None;
        }
    } else {
        return None;
    };

    let param = params.trim();
    let mut chars = param.chars();
    chars.next()?; // skip type char

    let reg_char = chars.next()?;
    if reg_char != 'r' && reg_char != 'R' {
        return None;
    }

    let digit = chars.next()?.to_digit(10)? as usize;
    let var_index = if reg_char == 'R' { digit + 10 } else { digit };

    state.variables.get(&var_index).map(|s| s.to_string())
}

fn handle_struct_operation(state: &mut NsisState, api_call: &str) {
    let paren_start = api_call.find('(');
    let paren_end = api_call.rfind(')');

    if paren_start.is_none() || paren_end.is_none() {
        return;
    }

    let struct_spec = &api_call[paren_start.unwrap() + 1..paren_end.unwrap()];
    let return_spec = &api_call[paren_end.unwrap() + 1..];

    if api_call.starts_with("*(&") {
        let ptr_addr = state.stack.len().to_string();
        debug!("Struct alloc: mock pointer {}", ptr_addr);
        store_result(state, return_spec, &ptr_addr);
        return;
    }

    let ptr_addr = if api_call.starts_with("*0") || api_call.starts_with("*1") {
        let reg_idx = if api_call.starts_with("*0") { 0 } else { 1 };
        state.variables.get(&reg_idx).map(|s| s.to_string())
    } else if api_call.starts_with('*') {
        let addr_end = api_call.find('(').unwrap_or(api_call.len());
        Some(api_call[1..addr_end].to_string())
    } else {
        None
    };

    if let Some(ptr_addr) = ptr_addr {
        MOCK_STRUCTS.with(|structs| {
            if let Some(field_values) = structs.borrow().get(&ptr_addr) {
                let fields: Vec<&str> = struct_spec.split(',').map(|s| s.trim()).collect();
                debug!("Struct read at {}: {} fields", ptr_addr, fields.len());

                for (idx, field) in fields.iter().enumerate() {
                    if let Some(value) = field_values.get(idx) {
                        if field.contains(".s") {
                            debug!("  Field {}: {} -> stack", idx, value);
                            state.stack.push(value.clone().into());
                        } else if field.contains(".r") || field.contains(".R") {
                            if let Some(dest_char) = field.chars().rev().nth(1) {
                                if let Some(digit) =
                                    field.chars().last().and_then(|c| c.to_digit(10))
                                {
                                    let var_index = if dest_char == 'R' {
                                        (digit + 10) as usize
                                    } else {
                                        digit as usize
                                    };
                                    debug!(
                                        "  Field {}: {} -> ${}",
                                        idx,
                                        value,
                                        if dest_char == 'R' {
                                            format!("R{}", digit)
                                        } else {
                                            digit.to_string()
                                        }
                                    );
                                    state.variables.insert(var_index, value.clone());
                                }
                            }
                        }
                    }
                }
            } else {
                debug!("No struct data found at pointer {}", ptr_addr);
            }
        });
    }
}

fn store_result(state: &mut NsisState, return_spec: &str, result: &str) {
    let return_spec = return_spec.trim();
    if return_spec.is_empty() {
        return;
    }

    let dest = if let Some(dot_pos) = return_spec.find('.') {
        &return_spec[dot_pos + 1..]
    } else {
        return;
    };

    match dest {
        "s" => {
            state.stack.push(result.to_owned().into());
        }
        dest if dest.len() >= 2 => {
            let reg_char = dest.chars().next().unwrap();
            if (reg_char == 'r' || reg_char == 'R') && dest.len() >= 2 {
                if let Some(digit) = dest.chars().nth(1).and_then(|c| c.to_digit(10)) {
                    let var_index = if reg_char == 'R' {
                        (digit + 10) as usize
                    } else {
                        digit as usize
                    };
                    state.variables.insert(var_index, result.to_owned());
                }
            }
        }
        _ => {}
    }
}
