use tracing::debug;

use crate::analysis::installers::nsis::state::NsisState;

/// https://github.com/NSIS-Dev/nsis/blob/v311/Contrib/System/Source/System.c#L444
pub fn evaluate(state: &mut NsisState) -> String {
    // NSIS Int64Op pops in this order: num1, op, num2
    // Stack layout: [num2, op, num1] (bottom to top) when called as "System::Int64Op num1 op num2"
    let arg1_str = state.stack.pop().unwrap_or_default();
    let operation = state.stack.pop().unwrap_or_default();
    let arg2_str = state.stack.pop().unwrap_or_default();

    debug!(
        "System: evaluating Int64Op '{}' '{}' '{}'",
        arg1_str, operation, arg2_str
    );

    let arg1 = parse_int64(&arg1_str).unwrap_or(0);
    let arg2 = parse_int64(&arg2_str).unwrap_or(0);

    evaluate_operation(&operation, arg1, Some(arg2))
}

/// Evaluate an Int64Op operation with given arguments
fn evaluate_operation(operation: &str, arg1: i64, arg2: Option<i64>) -> String {
    if arg2.is_none() {
        let result = match operation.trim() {
            "~" => !arg1,
            "!" => {
                if arg1 == 0 {
                    1
                } else {
                    0
                }
            }
            _ => arg1,
        };
        return result.to_string();
    }

    let arg2 = arg2.unwrap();

    let result = match operation.trim() {
        "+" => arg1.wrapping_add(arg2),
        "-" => arg1.wrapping_sub(arg2),
        "*" => arg1.wrapping_mul(arg2),
        "/" => {
            if arg2 != 0 {
                arg1.wrapping_div(arg2)
            } else {
                0
            }
        }
        "%" => {
            if arg2 != 0 {
                arg1.wrapping_rem(arg2)
            } else {
                0
            }
        }
        "<<" => arg1.wrapping_shl(arg2 as u32),
        ">>" => arg1.wrapping_shr(arg2 as u32),
        ">>>" => ((arg1 as u64) >> (arg2 as u32)) as i64,
        "|" => arg1 | arg2,
        "&" => arg1 & arg2,
        "^" => arg1 ^ arg2,
        "||" => {
            if arg1 != 0 || arg2 != 0 {
                1
            } else {
                0
            }
        }
        "&&" => {
            if arg1 != 0 && arg2 != 0 {
                1
            } else {
                0
            }
        }
        "<" => {
            if arg1 < arg2 {
                1
            } else {
                0
            }
        }
        "=" => {
            if arg1 == arg2 {
                1
            } else {
                0
            }
        }
        ">" => {
            if arg1 > arg2 {
                1
            } else {
                0
            }
        }
        _ => arg1,
    };

    result.to_string()
}

/// Parse a string as a 64-bit integer, supporting decimal, hex (0x), and octal (0) formats
fn parse_int64(s: &str) -> Option<i64> {
    let s = s.trim();

    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok().map(|v| v as i64)
    } else if s.starts_with('0') && s.len() > 1 && s.chars().nth(1).unwrap().is_ascii_digit() {
        i64::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse::<i64>().ok()
    }
}
