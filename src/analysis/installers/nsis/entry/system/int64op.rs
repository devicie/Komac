use tracing::debug;

use crate::analysis::installers::nsis::state::NsisState;

/// https://github.com/NSIS-Dev/nsis/blob/v311/Contrib/System/Source/System.c#L444
pub fn evaluate(state: &mut NsisState) -> String {
    let operation = state.stack.pop().unwrap_or_default();
    debug!("System: evaluating Int64Op operation='{}'", operation);

    // TODO use i64
    let arg1 = state.get_int(0);
    let arg2 = state.get_int(1);

    evaluate_operation(&operation, arg1.into(), Some(arg2.into()))
}

/// Evaluate an Int64Op operation with given arguments
fn evaluate_operation(operation: &str, arg1: i64, arg2: Option<i64>) -> String {
    // Check for unary operators (only one argument)
    if arg2.is_none() {
        let result = match operation.trim() {
            "~" => !arg1, // Bitwise not
            "!" => {
                if arg1 == 0 {
                    1
                } else {
                    0
                }
            } // Logical not
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
        ">>" => arg1.wrapping_shr(arg2 as u32), // Arithmetic shift
        ">>>" => ((arg1 as u64) >> (arg2 as u32)) as i64, // Logical shift
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
        // Octal
        i64::from_str_radix(&s[1..], 8).ok()
    } else {
        // Decimal (handles negative numbers)
        s.parse::<i64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addition() {
        assert_eq!(evaluate_operation("+", 5, Some(5)), "10");
        assert_eq!(
            evaluate_operation("*", 526355, Some(1565487)),
            "824001909885"
        );
    }

    #[test]
    fn test_division() {
        assert_eq!(
            evaluate_operation("/", 5498449498849818, Some(3)),
            "1832816499616606"
        );
    }

    #[test]
    fn test_modulo() {
        assert_eq!(
            evaluate_operation("%", 619736053874048620, Some(157)),
            "118"
        );
    }

    #[test]
    fn test_shift() {
        assert_eq!(evaluate_operation("<<", 1, Some(62)), "4611686018427387904");
        assert_eq!(evaluate_operation(">>", 4611686018427387904, Some(62)), "1");
        // Logical shift right
        assert_eq!(
            evaluate_operation(">>>", -9223372036854775808, Some(1)),
            "4611686018427387904"
        );
    }

    #[test]
    fn test_bitwise() {
        assert_eq!(
            evaluate_operation("&", 305419896, Some(4042322160)),
            "271581296"
        );
        assert_eq!(evaluate_operation("^", 1, Some(0)), "1");
    }

    #[test]
    fn test_logical() {
        assert_eq!(evaluate_operation("||", 1, Some(0)), "1");
        assert_eq!(evaluate_operation("&&", 1, Some(0)), "0");
    }

    #[test]
    fn test_comparison() {
        assert_eq!(
            evaluate_operation("<", 9302157012375, Some(570197509190760)),
            "1"
        );
        assert_eq!(evaluate_operation(">", 5168, Some(89873)), "0");
        assert_eq!(evaluate_operation("=", 189189, Some(189189)), "1");
    }

    #[test]
    fn test_unary() {
        assert_eq!(evaluate_operation("~", 156545668489, None), "-156545668490");
        assert_eq!(evaluate_operation("!", 1, None), "0");
        assert_eq!(evaluate_operation("!", 0, None), "1");
    }
}
