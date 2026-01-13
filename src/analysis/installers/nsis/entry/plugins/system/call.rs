use std::collections::HashMap;

use tracing::debug;

use crate::analysis::installers::nsis::state::NsisState;

thread_local! {
    static MOCK_STRUCTS: std::cell::RefCell<HashMap<String, Vec<String>>> = std::cell::RefCell::new(HashMap::new());
}

/// Represents a parsed parameter from a System::Call specification
/// Format: type [source] [destination]
#[derive(Debug, Clone)]
struct ParsedParam {
    /// The type (e.g., "i", "p", "*i", "t", etc.)
    param_type: String,
    /// The source (e.g., "s", "r0", "0", "'string'", ".", or None)
    source: Option<String>,
    /// The destination (e.g., "s", "r0", ".", or None)
    destination: Option<String>,
}

/// Parses a single parameter specification from NSIS System::Call
/// Format: type [source] [destination]
fn parse_param(param_str: &str) -> ParsedParam {
    let param_str = param_str.trim();
    if param_str.is_empty() {
        return ParsedParam {
            param_type: String::new(),
            source: None,
            destination: None,
        };
    }

    let mut chars = param_str.chars().peekable();
    let mut param_type = String::new();

    // Parse type - may start with * for pointer types
    if chars.peek() == Some(&'*') {
        param_type.push(chars.next().unwrap());
    }

    // Parse the base type character(s)
    // Types: v, p, b, h, i, l, m, t, w, g, k, @
    // Also: &vN, &iN, &l, &tN, &mN, &wN, &g16
    if chars.peek() == Some(&'&') {
        param_type.push(chars.next().unwrap());
        // Read the type letter and optional number
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphabetic() || c.is_ascii_digit() {
                param_type.push(chars.next().unwrap());
            } else {
                break;
            }
        }
    } else if let Some(&c) = chars.peek()
        && c.is_ascii_alphabetic() {
            param_type.push(chars.next().unwrap());
        }

    // Remaining string after the type
    let remaining: String = chars.collect();
    let remaining = remaining.trim();

    if remaining.is_empty() {
        return ParsedParam {
            param_type,
            source: None,
            destination: None,
        };
    }

    // Parse source and destination
    // Source/destination can be:
    // - "." (ignored)
    // - "n" (null/no output)
    // - "s" (stack)
    // - "r0" through "r9" ($0-$9)
    // - "r10" through "r19" or "R0" through "R9" ($R0-$R9)
    // - number (concrete value, may contain | for OR)
    // - 'string', "string", `string` (concrete string value)
    // - "c", "d", "o", "e", "a" (special NSIS variables)

    let (source, destination) = parse_source_and_destination(remaining);

    ParsedParam {
        param_type,
        source,
        destination,
    }
}

/// Parse source and destination from the remaining parameter string
fn parse_source_and_destination(s: &str) -> (Option<String>, Option<String>) {
    if s.is_empty() {
        return (None, None);
    }

    let mut chars = s.chars().peekable();
    let mut source = String::new();
    let mut destination = String::new();

    // Parse source
    if let Some(&c) = chars.peek() {
        if c == '\'' || c == '"' || c == '`' {
            // Quoted string - consume until matching quote
            let quote = chars.next().unwrap();
            source.push(quote);
            while let Some(&ch) = chars.peek() {
                source.push(chars.next().unwrap());
                if ch == quote {
                    break;
                }
            }
        } else if c == '.' {
            // Ignored
            source.push(chars.next().unwrap());
        } else if c == 'n' {
            // Null
            source.push(chars.next().unwrap());
        } else if c == 's' {
            // Stack
            source.push(chars.next().unwrap());
        } else if c == 'r' || c == 'R' {
            // Register (r0-r9, r10-r19, R0-R9)
            source.push(chars.next().unwrap());
            while let Some(&ch) = chars.peek() {
                if ch.is_ascii_digit() {
                    source.push(chars.next().unwrap());
                } else {
                    break;
                }
            }
        } else if c == 'c' || c == 'd' || c == 'o' || c == 'e' || c == 'a' {
            // Special NSIS variables
            source.push(chars.next().unwrap());
        } else if c.is_ascii_digit() || c == '-' {
            // Number (may contain |, 0x prefix with hex digits)
            // Track if we've seen 0x prefix for allowing hex digits
            let mut saw_hex_prefix = false;
            while let Some(&ch) = chars.peek() {
                if ch.is_ascii_digit() {
                    source.push(chars.next().unwrap());
                } else if ch == '-' || ch == '|' {
                    source.push(chars.next().unwrap());
                } else if ch == 'x' || ch == 'X' {
                    // 0x or 0X hex prefix
                    source.push(chars.next().unwrap());
                    saw_hex_prefix = true;
                } else if saw_hex_prefix && ch.is_ascii_hexdigit() {
                    // Hex digits after 0x prefix
                    source.push(chars.next().unwrap());
                } else {
                    // Stop at any other character (including 's', 'r', etc.)
                    break;
                }
            }
        }
    }

    // Parse destination (if any remaining)
    let remaining: String = chars.collect();
    let remaining = remaining.trim();

    if !remaining.is_empty() {
        let mut chars = remaining.chars().peekable();
        if let Some(&c) = chars.peek() {
            if c == '.' {
                destination.push(chars.next().unwrap());
            } else if c == 'n' {
                destination.push(chars.next().unwrap());
            } else if c == 's' {
                destination.push(chars.next().unwrap());
            } else if c == 'r' || c == 'R' {
                destination.push(chars.next().unwrap());
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_digit() {
                        destination.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
            }
        }
    }

    let source = if source.is_empty() || source == "." {
        None
    } else {
        Some(source)
    };

    let destination = if destination.is_empty() || destination == "." {
        None
    } else {
        Some(destination)
    };

    (source, destination)
}

/// Parse the parameters from a System::Call string
/// Returns a vector of parsed parameters
fn parse_params(params_and_return: &str) -> (Vec<ParsedParam>, Option<ParsedParam>) {
    // Find the parameter list between ( and )
    let paren_start = match params_and_return.find('(') {
        Some(pos) => pos,
        None => return (Vec::new(), None),
    };
    let paren_end = match params_and_return.rfind(')') {
        Some(pos) => pos,
        None => return (Vec::new(), None),
    };

    let params_str = &params_and_return[paren_start + 1..paren_end];
    let return_str = params_and_return[paren_end + 1..].trim();

    // Split parameters by comma, but respect quoted strings
    let param_strs = split_params(params_str);

    let params: Vec<ParsedParam> = param_strs.iter().map(|s| parse_param(s)).collect();

    let return_param = if !return_str.is_empty() {
        Some(parse_param(return_str))
    } else {
        None
    };

    (params, return_param)
}

/// Split parameters by comma, respecting quoted strings
fn split_params(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = ' ';

    for c in s.chars() {
        if in_quote {
            current.push(c);
            if c == quote_char {
                in_quote = false;
            }
        } else if c == '\'' || c == '"' || c == '`' {
            in_quote = true;
            quote_char = c;
            current.push(c);
        } else if c == ',' {
            result.push(current.trim().to_string());
            current = String::new();
        } else {
            current.push(c);
        }
    }

    if !current.is_empty() {
        result.push(current.trim().to_string());
    }

    result
}

/// Store a value to the specified destination
fn store_to_destination(state: &mut NsisState, dest: &str, value: &str) {
    match dest {
        "s" => {
            state.stack.push(value.to_owned().into());
        }
        dest if dest.starts_with('r') || dest.starts_with('R') => {
            if let Some(var_index) = parse_register(dest) {
                state.variables.insert(var_index, value.to_owned());
            }
        }
        _ => {}
    }
}

/// Parse a register specification (r0-r9, r10-r19, R0-R9) to variable index
fn parse_register(reg: &str) -> Option<usize> {
    let mut chars = reg.chars();
    let first = chars.next()?;
    let num_str: String = chars.collect();

    if num_str.is_empty() {
        return None;
    }

    let num: usize = num_str.parse().ok()?;

    match first {
        'r' => Some(num),      // r0-r9 -> 0-9, r10-r19 -> 10-19
        'R' => Some(num + 10), // R0-R9 -> 10-19
        _ => None,
    }
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

    let (params, return_param) = parse_params(params_and_return);

    // Consume parameters that read from the stack (source = "s")
    // We need to pop them to maintain correct stack state
    for param in &params {
        if let Some(ref source) = param.source
            && source == "s" {
                let _ = state.stack.pop();
            }
    }

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
                    // IsWow64Process2(hProcess, *pProcessMachine, *pNativeMachine)
                    // For native x64: pProcessMachine = IMAGE_FILE_MACHINE_AMD64, pNativeMachine = IMAGE_FILE_MACHINE_AMD64
                    // We need to write to the output parameters that have destinations
                    // Find parameters with pointer types (*i) that have destinations
                    for param in &params {
                        if param.param_type.starts_with('*')
                            && let Some(ref dest) = param.destination {
                                // IMAGE_FILE_MACHINE_AMD64 = 0x8664 = 34404
                                store_to_destination(state, dest, "34404");
                            }
                    }
                } else if params_and_return.contains("*i") {
                    debug!("{}: mocking WOW64=FALSE (native 64-bit)", function);
                    // For IsWow64Process, find the pointer parameter with a destination
                    for param in &params {
                        if param.param_type.starts_with('*')
                            && let Some(ref dest) = param.destination {
                                store_to_destination(state, dest, "0");
                            }
                    }
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
        "shell32" | "SHELL32" => match function {
            "SHChangeNotify" => "0",
            "SHGetKnownFolderPath" => {
                // Extract GUID from params (format: g "{GUID}")
                let guid = params_and_return.find('{').and_then(|start| {
                    params_and_return[start..]
                        .find('}')
                        .map(|end| &params_and_return[start..start + end + 1])
                });

                let path = match guid {
                    // FOLDERID_UserProgramFiles
                    Some("{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}") => {
                        Some("%LocalAppData%\\Programs")
                    }
                    // FOLDERID_LocalAppData
                    Some("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}") => Some("%LocalAppData%"),
                    // FOLDERID_RoamingAppData
                    Some("{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}") => Some("%AppData%"),
                    // FOLDERID_ProgramFiles
                    Some("{905E63B6-C1BF-494E-B29C-65B732D3D21A}") => Some("%ProgramFiles%"),
                    // FOLDERID_ProgramFilesX64
                    Some("{6D809377-6AF0-444B-8957-A3773F02200E}") => Some("%ProgramFiles%"),
                    // FOLDERID_ProgramFilesX86
                    Some("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}") => Some("%ProgramFiles(x86)%"),
                    _ => None,
                };

                if let Some(path) = path {
                    for param in &params {
                        if param.param_type == "*p"
                            && let Some(ref dest) = param.destination
                        {
                            let ptr = state.stack.len().to_string();
                            MOCK_STRUCTS.with(|structs| {
                                structs
                                    .borrow_mut()
                                    .insert(ptr.clone(), vec![path.to_string()]);
                            });
                            store_to_destination(state, dest, &ptr);
                        }
                    }
                    "0" // S_OK
                } else {
                    debug!("SHGetKnownFolderPath: unknown GUID {:?}", guid);
                    "1" // E_FAIL
                }
            }
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

    // Store the return value if there's a destination
    if let Some(ref ret) = return_param
        && let Some(ref dest) = ret.destination
    {
        store_to_destination(state, dest, result);
    }
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
        // Parse return spec and store result
        let return_param = parse_param(return_spec);
        if let Some(ref dest) = return_param.destination {
            store_to_destination(state, dest, &ptr_addr);
        }
        return;
    }

    // Parse pointer address from struct operation
    // *N = literal pointer value N
    // *rN or *RN = read pointer from register N
    let ptr_addr = if api_call.starts_with('*') {
        let addr_part = &api_call[1..api_call.find('(').unwrap_or(api_call.len())];
        if addr_part.starts_with('r') || addr_part.starts_with('R') {
            // Register reference - read from register
            parse_register(addr_part)
                .and_then(|reg_idx| state.variables.get(&reg_idx).map(|s| s.to_string()))
        } else {
            // Literal pointer value
            Some(addr_part.to_string())
        }
    } else {
        None
    };

    if let Some(ptr_addr) = ptr_addr {
        MOCK_STRUCTS.with(|structs| {
            if let Some(field_values) = structs.borrow().get(&ptr_addr) {
                let field_strs = split_params(struct_spec);
                debug!("Struct read at {}: {} fields", ptr_addr, field_strs.len());

                for (idx, field_str) in field_strs.iter().enumerate() {
                    if let Some(value) = field_values.get(idx) {
                        let param = parse_param(field_str);
                        if let Some(ref dest) = param.destination {
                            debug!("  Field {}: {} -> {}", idx, value, dest);
                            store_to_destination(state, dest, value);
                        }
                    }
                }
            } else {
                debug!("No struct data found at pointer {}", ptr_addr);
            }
        });
    }
}
