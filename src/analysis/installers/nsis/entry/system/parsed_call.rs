use super::super::super::strings::PredefinedVar;
use super::super::super::variables::Variables;

/// <https://nsis.sourceforge.io/Docs/System/System.html#callfuncs>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterType {
    Void,
    Pointer,
    Int8,
    Int16,
    Int32,
    Int64,
    Char,
    TChar,
    WChar,
    Guid,
    Callback,
    DirectRegister,
    StructPadding(u32),
    StructInt(u32),
    StructSize,
    StructTCharArray(u32),
    StructCharArray(u32),
    StructWCharArray(u32),
    StructGuid,
}

impl ParameterType {
    pub(super) fn parse(s: &str) -> Option<(Self, usize)> {
        if let Some(inner) = s.strip_prefix('&') {
            let letter = inner.chars().next()?;
            let after = &inner[letter.len_utf8()..];
            let digits_end = after
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(after.len());
            let n: u32 = after[..digits_end].parse().unwrap_or(0);
            let consumed = 1 + letter.len_utf8() + digits_end;
            let ty = match letter {
                'v' => Self::StructPadding(n),
                'i' => Self::StructInt(n),
                'l' => Self::StructSize,
                't' => Self::StructTCharArray(n),
                'm' => Self::StructCharArray(n),
                'w' => Self::StructWCharArray(n),
                'g' => Self::StructGuid,
                _ => return None,
            };
            Some((ty, consumed))
        } else {
            let c = s.chars().next()?;
            let ty = match c {
                'v' => Self::Void,
                'p' => Self::Pointer,
                'b' => Self::Int8,
                'h' => Self::Int16,
                'i' => Self::Int32,
                'l' => Self::Int64,
                'm' => Self::Char,
                't' => Self::TChar,
                'w' => Self::WChar,
                'g' => Self::Guid,
                'k' => Self::Callback,
                '@' => Self::DirectRegister,
                _ => return None,
            };
            Some((ty, 1))
        }
    }
}

/// Source operand for a NSIS System call parameter.
///
/// <https://nsis.sourceforge.io/Docs/System/System.html#callfuncs>
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Source<'a> {
    Ignored,
    Stack,
    Null,
    Register(usize),
    Int(i64),
    Str(&'a str),
}

impl<'a> Source<'a> {
    pub fn parse(s: &'a str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        match s {
            "." => return Some(Self::Ignored),
            "s" => return Some(Self::Stack),
            "n" => return Some(Self::Null),
            "c" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::CmdLine as usize,
                ));
            }
            "d" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::InstDir as usize,
                ));
            }
            "o" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::OutDir as usize,
                ));
            }
            "e" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::ExeDir as usize,
                ));
            }
            "a" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::Language as usize,
                ));
            }
            _ => {}
        }
        if let Some(rest) = s.strip_prefix('r') {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = rest.parse::<usize>() {
                    if n < 20 {
                        return Some(Self::Register(n));
                    }
                }
            }
        }
        if let Some(rest) = s.strip_prefix('R') {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = rest.parse::<usize>() {
                    if n < 10 {
                        return Some(Self::Register(10 + n));
                    }
                }
            }
        }
        if let Some(q) = s
            .chars()
            .next()
            .filter(|&c| c == '\'' || c == '"' || c == '`')
        {
            let inner = &s[1..];
            let close = inner.rfind(q).unwrap_or(inner.len());
            return Some(Self::Str(&inner[..close]));
        }
        if s.starts_with('$') {
            if s.len() == 2 {
                if let Some(n) = s[1..].parse::<usize>().ok().filter(|&n| n < 10) {
                    return Some(Self::Register(n));
                }
            }
            if let Some(rest) = s.strip_prefix("$R") {
                if let Ok(n) = rest.parse::<usize>() {
                    if n < 10 {
                        return Some(Self::Register(10 + n));
                    }
                }
            }
            let idx = PredefinedVar::all()
                .iter()
                .position(|v| v.as_str() == s)
                .or_else(|| match s {
                    "$INSTDIR" => Some(PredefinedVar::InstDir as usize),
                    "$TEMP" => Some(PredefinedVar::Temp as usize),
                    "$PLUGINSDIR" => Some(PredefinedVar::PluginsDir as usize),
                    _ => None,
                });
            return idx.map(|i| Self::Register(Variables::NUM_REGISTERS + i));
        }
        if s.starts_with(|c: char| c.is_ascii_digit() || c == '-') || s.contains('|') {
            let mut n = 0i64;
            let mut valid = true;
            for part in s.split('|') {
                let part = part.trim();
                let parsed = if let Some(hex) =
                    part.strip_prefix("0x").or_else(|| part.strip_prefix("0X"))
                {
                    i64::from_str_radix(hex, 16).ok()
                } else {
                    part.parse::<i64>().ok()
                };
                match parsed {
                    Some(v) => n |= v,
                    None => {
                        valid = false;
                        break;
                    }
                }
            }
            if valid {
                return Some(Self::Int(n));
            }
        }
        Some(Self::Str(s))
    }
}

/// Destination operand for a NSIS System call parameter.
///
/// <https://nsis.sourceforge.io/Docs/System/System.html#callfuncs>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Ignored,
    Stack,
    Null,
    Register(usize),
}

impl Destination {
    pub fn parse(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        match s {
            "." => return Some(Self::Ignored),
            "s" => return Some(Self::Stack),
            "n" => return Some(Self::Null),
            "c" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::CmdLine as usize,
                ));
            }
            "d" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::InstDir as usize,
                ));
            }
            "o" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::OutDir as usize,
                ));
            }
            "e" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::ExeDir as usize,
                ));
            }
            "a" => {
                return Some(Self::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::Language as usize,
                ));
            }
            _ => {}
        }
        if let Some(rest) = s.strip_prefix('r') {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = rest.parse::<usize>() {
                    if n < 20 {
                        return Some(Self::Register(n));
                    }
                }
            }
        }
        if let Some(rest) = s.strip_prefix('R') {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = rest.parse::<usize>() {
                    if n < 10 {
                        return Some(Self::Register(10 + n));
                    }
                }
            }
        }
        None
    }
}

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub struct Parameter<'a> {
    pointer: bool,
    ty: ParameterType,
    source: Option<Source<'a>>,
    destination: Option<Destination>,
}

#[allow(dead_code)]
impl<'a> Parameter<'a> {
    pub fn parse(s: &'a str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (pointer, s) = s.strip_prefix('*').map_or((false, s), |r| (true, r));
        let (ty, consumed) = ParameterType::parse(s)?;
        let rest = s[consumed..].trim_start();

        let is_reg_token = |t: &str| -> bool {
            match t.bytes().next() {
                Some(b's' | b'n' | b'c' | b'd' | b'o' | b'e' | b'a') if t.len() == 1 => true,
                Some(b'r' | b'R') => t.len() > 1 && t[1..].bytes().all(|b| b.is_ascii_digit()),
                _ => false,
            }
        };

        let (source, destination) = if rest.is_empty() {
            (None, None)
        } else if let Some(dest_str) = rest.strip_prefix('.') {
            (None, Destination::parse(dest_str.trim()))
        } else if let Some(q) = rest
            .bytes()
            .next()
            .filter(|&b| b == b'\'' || b == b'"' || b == b'`')
        {
            let q = q as char;
            let inner = &rest[1..];
            let close = inner.rfind(q).unwrap_or(inner.len());
            let after = rest[close + 2..].trim_start();
            let dest = after
                .strip_prefix('.')
                .and_then(|d| Destination::parse(d.trim()));
            (Source::parse(&rest[..close + 2]), dest)
        } else {
            // Find first `.` that isn't inside a `0x` hex prefix.
            let dot = {
                let b = rest.as_bytes();
                let mut pos = None;
                let mut i = 0;
                while i < rest.len() {
                    if b[i] == b'0' && i + 1 < rest.len() && (b[i + 1] == b'x' || b[i + 1] == b'X')
                    {
                        i += 2;
                        while i < rest.len() && b[i].is_ascii_hexdigit() {
                            i += 1;
                        }
                    } else if b[i] == b'.' {
                        pos = Some(i);
                        break;
                    } else {
                        i += 1;
                    }
                }
                pos
            };
            if let Some(pos) = dot {
                let src = rest[..pos].trim();
                let dest_str = rest[pos + 1..].trim();
                (
                    if src.is_empty() {
                        None
                    } else {
                        Source::parse(src)
                    },
                    Destination::parse(dest_str),
                )
            } else if let Some(sp) = rest.rfind(|c: char| c.is_ascii_whitespace()) {
                let tail = rest[sp + 1..].trim();
                if is_reg_token(tail) {
                    let src = rest[..sp].trim();
                    (
                        if src.is_empty() {
                            None
                        } else {
                            Source::parse(src)
                        },
                        Destination::parse(tail),
                    )
                } else {
                    (Source::parse(rest), None)
                }
            } else {
                // Compact numeric+dest: `0s`, `-1r0`.
                let num_end = {
                    let b = rest.as_bytes();
                    let mut j = if b.first() == Some(&b'-') { 1 } else { 0 };
                    if j + 1 < b.len() && b[j] == b'0' && (b[j + 1] == b'x' || b[j + 1] == b'X') {
                        j += 2;
                        while j < b.len() && b[j].is_ascii_hexdigit() {
                            j += 1;
                        }
                    } else {
                        while j < b.len() && b[j].is_ascii_digit() {
                            j += 1;
                        }
                    }
                    j
                };
                if num_end > 0 && num_end < rest.len() && is_reg_token(&rest[num_end..]) {
                    (
                        Source::parse(&rest[..num_end]),
                        Destination::parse(&rest[num_end..]),
                    )
                } else {
                    (Source::parse(rest), None)
                }
            }
        };

        Some(Self {
            pointer,
            ty,
            source,
            destination,
        })
    }

    #[inline]
    pub const fn pointer(&self) -> bool {
        self.pointer
    }

    #[inline]
    pub const fn ty(&self) -> ParameterType {
        self.ty
    }

    #[inline]
    pub fn source(&self) -> Option<Source<'a>> {
        self.source
    }

    #[inline]
    pub fn destination(&self) -> Option<Destination> {
        self.destination
    }
}

/// The procedure to call in a NSIS `System::Call` or `System::Get` invocation.
///
/// <https://nsis.sourceforge.io/Docs/System/System.html#callfuncs>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proc<'a> {
    /// `DLL::FUNC` — exported function from a DLL.
    DllExport { dll: &'a str, func: &'a str },
    /// `::ADDR` — function at an absolute address.
    Address(&'a str),
    /// `*ADDR` — struct located at an address, or `*` (empty) for a new struct allocation.
    StructPtr(&'a str),
    /// `IPTR->IDX` — COM vtable member call.
    ComVtable { iptr: &'a str, idx: u32 },
    /// Bare value (a proc returned by a previous `System::Get` call).
    ProcValue(&'a str),
    /// Empty proc — creates a new callback function (used with `System::Get`).
    Callback,
}

impl<'a> Proc<'a> {
    /// Parses the proc portion of a System call string (everything before the first `(`).
    pub fn parse(s: &'a str) -> Self {
        // `*ADDR(...)` or `*(...)` — struct pointer
        if let Some(rest) = s.strip_prefix('*') {
            return Self::StructPtr(rest.trim());
        }

        // `::ADDR` — function at address
        if let Some(addr) = s.strip_prefix("::") {
            return Self::Address(addr.trim());
        }

        // `IPTR->IDX` — COM vtable member
        if let Some(arrow) = s.find("->") {
            let iptr = s[..arrow].trim();
            let idx_str = s[arrow + 2..].trim();
            if let Ok(idx) = idx_str.parse::<u32>() {
                return Self::ComVtable { iptr, idx };
            }
        }

        // `DLL::FUNC` — exported function (module may be quoted)
        if let Some(sep) = find_module_sep(s) {
            let dll = s[..sep].trim().trim_matches('"').trim_matches('\'');
            let func = s[sep + 2..].trim();
            return Self::DllExport { dll, func };
        }

        // Empty string → new callback
        if s.is_empty() {
            return Self::Callback;
        }

        // Bare value (proc returned by Get)
        Self::ProcValue(s.trim())
    }
}

/// Finds the `::` separator that splits a DLL name from a function name, skipping `::` that
/// appear inside a leading quoted path like `"$SYSDIR\mylib.dll"::MyFunc`.
fn find_module_sep(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;

    // Skip over an optional leading quoted string (the DLL path).
    if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
        let q = bytes[i];
        i += 1;
        while i < bytes.len() && bytes[i] != q {
            i += 1;
        }
        if i < bytes.len() {
            i += 1; // consume closing quote
        }
    }

    // Walk forward looking for `::`.
    while i + 1 < bytes.len() {
        if bytes[i] == b':' && bytes[i + 1] == b':' {
            return Some(i);
        }
        i += 1;
    }

    None
}

/// Calling convention and behaviour modifiers following `?`.
///
/// <https://nsis.sourceforge.io/Docs/System/System.html#callfuncs>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options {
    pub cdecl: bool,
    pub always_return: bool,
    pub no_redefine: bool,
    pub stack_return: bool,
    pub get_last_error: bool,
    pub unload_dll: bool,
    pub v2_syntax: bool,
}

impl Options {
    fn parse(s: &str) -> Self {
        let mut opts = Self::default();
        let mut negate = false;
        for c in s.chars() {
            match c {
                '!' => negate = true,
                'c' => {
                    opts.cdecl = !negate;
                    negate = false;
                }
                'r' => {
                    opts.always_return = !negate;
                    negate = false;
                }
                'n' => {
                    opts.no_redefine = !negate;
                    negate = false;
                }
                's' => {
                    opts.stack_return = !negate;
                    negate = false;
                }
                'e' => {
                    opts.get_last_error = !negate;
                    negate = false;
                }
                'u' => {
                    opts.unload_dll = !negate;
                    negate = false;
                }
                '2' => {
                    opts.v2_syntax = !negate;
                    negate = false;
                }
                _ => {
                    negate = false;
                }
            }
        }
        opts
    }
}

#[allow(dead_code)]
pub struct ParsedCall<'a> {
    proc: Proc<'a>,
    return_type: ParameterType,
    parameters: Vec<Parameter<'a>>,
    return_destination: Destination,
    options: Options,
}

#[allow(dead_code)]
impl<'a> ParsedCall<'a> {
    pub fn parse(input: &'a str) -> Option<Self> {
        // Everything up to the first `(` is the proc spec. Find that `(`.
        let paren_open = input.find('(')?;
        let proc_str = input[..paren_open].trim();

        let proc = Proc::parse(proc_str);

        // Find the matching closing `)` for the parameter list.
        let after_open = &input[paren_open + 1..];
        let param_close = find_matching_paren(after_open)?;
        let raw_params = &after_open[..param_close];
        let rest = after_open[param_close + 1..].trim_start();

        // Optional `? OPTIONS` suffix.
        let (rest, options) = if let Some(opt_pos) = rest.find('?') {
            (
                rest[..opt_pos].trim_end(),
                Options::parse(rest[opt_pos + 1..].trim()),
            )
        } else {
            (rest, Options::default())
        };

        // Optional return type + destination: e.g. `i.r3`, `p .s`, `.r0`.
        let type_end = rest
            .find(|c: char| c.is_whitespace() || c == '(' || c == '.')
            .unwrap_or(rest.len());
        let return_type = ParameterType::parse(&rest[..type_end])
            .map(|(t, _)| t)
            .unwrap_or(ParameterType::Int32);
        let after_type = rest[type_end..].trim_start();

        // Optional v2-style value list: `(val, val, ...)` followed by destination.
        let (parameters, return_destination) = if let Some(rest) = after_type.strip_prefix('(') {
            // For DLL::FUNC with separate type list, raw_params holds types and this holds values.
            // For struct / other procs the raw_params are already `type+src+dest` specs.
            let close = rest.rfind(')')?;
            let values_str = &rest[..close];
            let after = &rest[close + 1..];
            let dest_str = after.trim_start().trim_start_matches('.').trim();
            let return_dest = Destination::parse(dest_str).unwrap_or(Destination::Ignored);

            let types: Vec<&str> = raw_params
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();

            let params = values_str
                .split(',')
                .map(str::trim)
                .zip(types.iter().copied().chain(std::iter::repeat("")))
                .filter_map(|(val, ty_str)| {
                    if val.is_empty() {
                        return None;
                    }
                    let pointer = ty_str.starts_with('*');
                    let base = if pointer { &ty_str[1..] } else { ty_str };
                    let (ty, _) = ParameterType::parse(base)?;
                    Some(Parameter {
                        pointer,
                        ty,
                        source: Source::parse(val),
                        destination: None,
                    })
                })
                .collect();

            (params, return_dest)
        } else {
            let dest_str = after_type.trim_start_matches('.').trim();
            let return_dest = Destination::parse(dest_str).unwrap_or(Destination::Ignored);
            let params = raw_params
                .split(',')
                .filter_map(|s| Parameter::parse(s))
                .collect();
            (params, return_dest)
        };

        Some(Self {
            proc,
            return_type,
            parameters,
            return_destination,
            options,
        })
    }

    /// Returns the parsed proc descriptor.
    #[inline]
    pub const fn proc(&self) -> Proc<'a> {
        self.proc
    }

    /// Returns the DLL module name for [`Proc::DllExport`] procs, or `""` for all others.
    #[inline]
    pub fn module(&self) -> &str {
        match self.proc {
            Proc::DllExport { dll, .. } => dll,
            _ => "",
        }
    }

    /// Returns the function/ordinal name for [`Proc::DllExport`] procs, or `""` for all others.
    #[inline]
    pub fn function(&self) -> &str {
        match self.proc {
            Proc::DllExport { func, .. } => func,
            _ => "",
        }
    }

    /// Returns the return-value type.
    #[inline]
    pub const fn return_type(&self) -> ParameterType {
        self.return_type
    }

    /// Returns the parsed call parameters.
    #[inline]
    pub fn parameters(&self) -> &[Parameter<'a>] {
        self.parameters.as_slice()
    }

    /// Returns the destination for the return value (defaults to `Register(0)` when unspecified).
    #[inline]
    pub const fn return_destination(&self) -> Destination {
        self.return_destination
    }

    /// Returns the calling convention and behaviour modifiers, if any were given after `?`.
    #[inline]
    pub const fn options(&self) -> Options {
        self.options
    }
}

/// Finds the index of the `)` that closes the `(` already consumed, respecting nested parens.
fn find_matching_paren(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                if depth == 0 {
                    return Some(i);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::super::super::strings::PredefinedVar;
    use super::super::super::super::variables::Variables;
    use super::{Destination, Options, Parameter, ParameterType, ParsedCall, Proc, Source};

    fn p<'a>(
        pointer: bool,
        ty: ParameterType,
        source: Option<Source<'a>>,
        destination: Option<Destination>,
    ) -> Parameter<'a> {
        Parameter {
            pointer,
            ty,
            source,
            destination,
        }
    }

    use ParameterType::*;

    #[test]
    fn parses_set_environment_variable() {
        let call = ParsedCall::parse(
            "Kernel32::SetEnvironmentVariable(t, t)i \
             (\"PORTABLE_EXECUTABLE_APP_FILENAME\", \"bitwarden\").r0",
        )
        .unwrap();

        assert_eq!(call.module(), "Kernel32");
        assert_eq!(call.function(), "SetEnvironmentVariable");
        assert_eq!(
            call.proc(),
            Proc::DllExport {
                dll: "Kernel32",
                func: "SetEnvironmentVariable"
            }
        );
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Register(0));
        assert_eq!(
            call.parameters(),
            &[
                p(
                    false,
                    TChar,
                    Some(Source::Str("PORTABLE_EXECUTABLE_APP_FILENAME")),
                    None
                ),
                p(false, TChar, Some(Source::Str("bitwarden")), None),
            ]
        );
    }

    #[test]
    fn parses_get_current_process() {
        let call = ParsedCall::parse("kernel32::GetCurrentProcess()p.s").unwrap();

        assert_eq!(call.module(), "kernel32");
        assert_eq!(call.function(), "GetCurrentProcess");
        assert_eq!(
            call.proc(),
            Proc::DllExport {
                dll: "kernel32",
                func: "GetCurrentProcess"
            }
        );
        assert_eq!(call.return_type(), Pointer);
        assert_eq!(call.return_destination(), Destination::Stack);
        assert_eq!(call.parameters(), &[]);
    }

    #[test]
    fn parses_is_wow64_process() {
        let call = ParsedCall::parse("kernel32::IsWow64Process(p-1,*i0s)").unwrap();

        assert_eq!(call.module(), "kernel32");
        assert_eq!(call.function(), "IsWow64Process");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(
            call.parameters(),
            &[
                p(false, Pointer, Some(Source::Int(-1)), None),
                p(true, Int32, Some(Source::Int(0)), Some(Destination::Stack)),
            ]
        );
    }

    #[test]
    fn parses_is_wow64_process2() {
        let call = ParsedCall::parse("kernel32::IsWow64Process2(ps,*i,*i0s)").unwrap();

        assert_eq!(call.module(), "kernel32");
        assert_eq!(call.function(), "IsWow64Process2");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(
            call.parameters(),
            &[
                p(false, Pointer, Some(Source::Stack), None),
                p(true, Int32, None, None),
                p(true, Int32, Some(Source::Int(0)), Some(Destination::Stack)),
            ]
        );
    }

    #[test]
    fn parses_get_version_ex() {
        let call = ParsedCall::parse("kernel32::GetVersionEx(pr0)i.r3").unwrap();

        assert_eq!(call.module(), "kernel32");
        assert_eq!(call.function(), "GetVersionEx");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Register(3));
        assert_eq!(
            call.parameters(),
            &[p(false, Pointer, Some(Source::Register(0)), None)]
        );
    }

    #[test]
    fn parses_message_box() {
        let call = ParsedCall::parse(
            "user32::MessageBox(p $HWNDPARENT, t 'NSIS System Plug-in', t 'Test', i 0)",
        )
        .unwrap();

        assert_eq!(call.module(), "user32");
        assert_eq!(call.function(), "MessageBox");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[
                p(
                    false,
                    Pointer,
                    Some(Source::Register(
                        Variables::NUM_REGISTERS + PredefinedVar::WindowParent as usize
                    )),
                    None
                ),
                p(false, TChar, Some(Source::Str("NSIS System Plug-in")), None),
                p(false, TChar, Some(Source::Str("Test")), None),
                p(false, Int32, Some(Source::Int(0)), None),
            ]
        );
    }

    #[test]
    fn parses_get_module_handle() {
        let call = ParsedCall::parse("kernel32::GetModuleHandle(t 'user32.dll') p .s").unwrap();

        assert_eq!(call.module(), "kernel32");
        assert_eq!(call.function(), "GetModuleHandle");
        assert_eq!(call.return_type(), Pointer);
        assert_eq!(call.return_destination(), Destination::Stack);
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[p(false, TChar, Some(Source::Str("user32.dll")), None)]
        );
    }

    #[test]
    fn parses_get_proc_address() {
        let call =
            ParsedCall::parse("kernel32::GetProcAddress(p s, m 'MessageBoxA') p .r0").unwrap();

        assert_eq!(call.module(), "kernel32");
        assert_eq!(call.function(), "GetProcAddress");
        assert_eq!(call.return_type(), Pointer);
        assert_eq!(call.return_destination(), Destination::Register(0));
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[
                p(false, Pointer, Some(Source::Stack), None),
                p(false, Char, Some(Source::Str("MessageBoxA")), None),
            ]
        );
    }

    #[test]
    fn parses_get_user_name() {
        let call = ParsedCall::parse("advapi32::GetUserName(t .r0, *i 1024 r1) i.r2").unwrap();

        assert_eq!(call.module(), "advapi32");
        assert_eq!(call.function(), "GetUserName");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Register(2));
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[
                p(false, TChar, None, Some(Destination::Register(0))),
                p(
                    true,
                    Int32,
                    Some(Source::Int(1024)),
                    Some(Destination::Register(1))
                ),
            ]
        );
    }

    #[test]
    fn parses_load_library() {
        let call = ParsedCall::parse(r#"KERNEL32::LoadLibrary(t "test.dll")p.r1"#).unwrap();

        assert_eq!(call.module(), "KERNEL32");
        assert_eq!(call.function(), "LoadLibrary");
        assert_eq!(call.return_type(), Pointer);
        assert_eq!(call.return_destination(), Destination::Register(1));
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[p(false, TChar, Some(Source::Str("test.dll")), None)]
        );
    }

    #[test]
    fn parses_get_window_text() {
        let call = ParsedCall::parse("user32::GetWindowText(pr1,t.r2,i256)").unwrap();

        assert_eq!(call.module(), "user32");
        assert_eq!(call.function(), "GetWindowText");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[
                p(false, Pointer, Some(Source::Register(1)), None),
                p(false, TChar, None, Some(Destination::Register(2))),
                p(false, Int32, Some(Source::Int(256)), None),
            ]
        );
    }

    #[test]
    fn parses_enum_child_windows() {
        let call =
            ParsedCall::parse("user32::EnumChildWindows(p $HWNDPARENT, k R0, p) i.s").unwrap();

        assert_eq!(call.module(), "user32");
        assert_eq!(call.function(), "EnumChildWindows");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Stack);
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[
                p(
                    false,
                    Pointer,
                    Some(Source::Register(
                        Variables::NUM_REGISTERS + PredefinedVar::WindowParent as usize
                    )),
                    None
                ),
                p(false, Callback, Some(Source::Register(10)), None),
                p(false, Pointer, None, None),
            ]
        );
    }

    #[test]
    fn parses_quoted_dll_path() {
        let call = ParsedCall::parse(r#""$SYSDIR\mylib.dll"::MyFunction(i 42)"#).unwrap();

        assert_eq!(call.module(), r"$SYSDIR\mylib.dll");
        assert_eq!(call.function(), "MyFunction");
        assert_eq!(
            call.proc(),
            Proc::DllExport {
                dll: r"$SYSDIR\mylib.dll",
                func: "MyFunction"
            }
        );
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[p(false, Int32, Some(Source::Int(42)), None)]
        );
    }

    #[test]
    fn parses_function_ordinal() {
        let call = ParsedCall::parse("shell32::#18(i 0) i.r0").unwrap();

        assert_eq!(call.module(), "shell32");
        assert_eq!(call.function(), "#18");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Register(0));
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[p(false, Int32, Some(Source::Int(0)), None)]
        );
    }

    #[test]
    fn parses_unload_option() {
        let call = ParsedCall::parse("MyDLL::MyFunc(i 5) ? u").unwrap();

        assert_eq!(call.module(), "MyDLL");
        assert_eq!(call.function(), "MyFunc");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(
            call.options(),
            Options {
                unload_dll: true,
                ..Options::default()
            }
        );
        assert_eq!(
            call.parameters(),
            &[p(false, Int32, Some(Source::Int(5)), None)]
        );
    }

    #[test]
    fn parses_getlasterror_option() {
        let call = ParsedCall::parse(
            "user32::SendMessage(p $HWNDPARENT, t 'test', t 'test', p 0) p.s ? e",
        )
        .unwrap();

        assert_eq!(call.module(), "user32");
        assert_eq!(call.function(), "SendMessage");
        assert_eq!(call.return_type(), Pointer);
        assert_eq!(call.return_destination(), Destination::Stack);
        assert_eq!(
            call.options(),
            Options {
                get_last_error: true,
                ..Options::default()
            }
        );
        assert_eq!(
            call.parameters(),
            &[
                p(
                    false,
                    Pointer,
                    Some(Source::Register(
                        Variables::NUM_REGISTERS + PredefinedVar::WindowParent as usize
                    )),
                    None
                ),
                p(false, TChar, Some(Source::Str("test")), None),
                p(false, TChar, Some(Source::Str("test")), None),
                p(false, Pointer, Some(Source::Int(0)), None),
            ]
        );
    }

    #[test]
    fn parses_cdecl_option() {
        let call = ParsedCall::parse("mylib::CdeclFunc(i r0, i r1) i.r2 ? c").unwrap();

        assert_eq!(call.module(), "mylib");
        assert_eq!(call.function(), "CdeclFunc");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Register(2));
        assert_eq!(
            call.options(),
            Options {
                cdecl: true,
                ..Options::default()
            }
        );
        assert_eq!(
            call.parameters(),
            &[
                p(false, Int32, Some(Source::Register(0)), None),
                p(false, Int32, Some(Source::Register(1)), None),
            ]
        );
    }

    #[test]
    fn parses_co_create_instance() {
        let call =
            ParsedCall::parse("ole32::CoCreateInstance(g 'CLSID', p 0, i 1, g 'IID', *p .r0) i.r1")
                .unwrap();

        assert_eq!(call.module(), "ole32");
        assert_eq!(call.function(), "CoCreateInstance");
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Register(1));
        assert_eq!(call.options(), Options::default());
        assert_eq!(
            call.parameters(),
            &[
                p(false, Guid, Some(Source::Str("CLSID")), None),
                p(false, Pointer, Some(Source::Int(0)), None),
                p(false, Int32, Some(Source::Int(1)), None),
                p(false, Guid, Some(Source::Str("IID")), None),
                p(true, Pointer, None, Some(Destination::Register(0))),
            ]
        );
    }

    #[test]
    fn parses_co_create_instance2() {
        let call =
            ParsedCall::parse("*(i.s,i.r1,i.r2,i.r3,i.s,&t128.s,&i2.s,&i2,&i2,&i1.s,&i1)").unwrap();

        assert_eq!(call.proc(), Proc::StructPtr(""));
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(
            call.parameters(),
            &[
                p(false, Int32, None, Some(Destination::Stack)),
                p(false, Int32, None, Some(Destination::Register(1))),
                p(false, Int32, None, Some(Destination::Register(2))),
                p(false, Int32, None, Some(Destination::Register(3))),
                p(false, Int32, None, Some(Destination::Stack)),
                p(false, StructTCharArray(128), None, Some(Destination::Stack)),
                p(false, StructInt(2), None, Some(Destination::Stack)),
                p(false, StructInt(2), None, None),
                p(false, StructInt(2), None, None),
                p(false, StructInt(1), None, Some(Destination::Stack)),
                p(false, StructInt(1), None, None),
            ]
        );
    }

    #[test]
    fn parses_struct_ptr_with_address() {
        // `*$0(i 5)` — write int 5 into struct at address in $0
        let call = ParsedCall::parse("*$0(i 5)").unwrap();

        assert_eq!(call.proc(), Proc::StructPtr("$0"));
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(
            call.parameters(),
            &[p(false, Int32, Some(Source::Int(5)), None)]
        );
    }

    #[test]
    fn parses_struct_ptr_read() {
        // `*$0(i .r1)` — read int from struct at $0 into r1
        let call = ParsedCall::parse("*$0(i .r1)").unwrap();

        assert_eq!(call.proc(), Proc::StructPtr("$0"));
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(
            call.parameters(),
            &[p(false, Int32, None, Some(Destination::Register(1)))]
        );
    }

    #[test]
    fn parses_new_struct_allocation() {
        // `*(i, i, i, t)p.s` — allocate a new struct
        let call = ParsedCall::parse("*(i, i, i, t)p.s").unwrap();

        assert_eq!(call.proc(), Proc::StructPtr(""));
        assert_eq!(call.return_type(), Pointer);
        assert_eq!(call.return_destination(), Destination::Stack);
        assert_eq!(
            call.parameters(),
            &[
                p(false, Int32, None, None),
                p(false, Int32, None, None),
                p(false, Int32, None, None),
                p(false, TChar, None, None),
            ]
        );
    }

    #[test]
    fn parses_function_at_address() {
        // `::$0(p $HWNDPARENT, m 'Hello', m 'Title', i 0)` — call function at address in $0
        let call = ParsedCall::parse("::$0(p $HWNDPARENT, m 'Hello', m 'Title', i 0)").unwrap();

        assert_eq!(call.proc(), Proc::Address("$0"));
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(
            call.parameters(),
            &[
                p(
                    false,
                    Pointer,
                    Some(Source::Register(
                        Variables::NUM_REGISTERS + PredefinedVar::WindowParent as usize
                    )),
                    None
                ),
                p(false, Char, Some(Source::Str("Hello")), None),
                p(false, Char, Some(Source::Str("Title")), None),
                p(false, Int32, Some(Source::Int(0)), None),
            ]
        );
    }

    #[test]
    fn parses_com_vtable() {
        // `$0->4(w .r2, i 256, i 0)` — COM method call
        let call = ParsedCall::parse("$0->4(w .r2, i 256, i 0)").unwrap();

        assert_eq!(call.proc(), Proc::ComVtable { iptr: "$0", idx: 4 });
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Ignored);
        assert_eq!(
            call.parameters(),
            &[
                p(false, WChar, None, Some(Destination::Register(2))),
                p(false, Int32, Some(Source::Int(256)), None),
                p(false, Int32, Some(Source::Int(0)), None),
            ]
        );
    }

    #[test]
    fn parses_com_release() {
        // `$0->2()` — COM Release()
        let call = ParsedCall::parse("$0->2()").unwrap();

        assert_eq!(call.proc(), Proc::ComVtable { iptr: "$0", idx: 2 });
        assert_eq!(call.parameters(), &[]);
        assert_eq!(call.return_destination(), Destination::Ignored);
    }

    #[test]
    fn parses_proc_value() {
        // `$R0` — call a stored proc value
        let call = ParsedCall::parse("$R0(i r0, i r1) i.r2").unwrap();

        assert_eq!(call.proc(), Proc::ProcValue("$R0"));
        assert_eq!(call.return_type(), Int32);
        assert_eq!(call.return_destination(), Destination::Register(2));
        assert_eq!(
            call.parameters(),
            &[
                p(false, Int32, Some(Source::Register(0)), None),
                p(false, Int32, Some(Source::Register(1)), None),
            ]
        );
    }

    #[test]
    fn parses_callback_creation() {
        // `(i .r0, i .r1) isR0` — new callback (no proc name, used with System::Get)
        let call = ParsedCall::parse("(i .r0, i .r1) isR0").unwrap();

        assert_eq!(call.proc(), Proc::Callback);
        assert_eq!(call.return_type(), Int32);
        assert_eq!(
            call.parameters(),
            &[
                p(false, Int32, None, Some(Destination::Register(0))),
                p(false, Int32, None, Some(Destination::Register(1))),
            ]
        );
    }

    #[test]
    fn parameter_parse_simple_int_literal() {
        assert_eq!(
            Parameter::parse("i 42"),
            Some(p(false, Int32, Some(Source::Int(42)), None))
        );
    }

    #[test]
    fn parameter_parse_pointer_type_with_source_and_dest() {
        assert_eq!(
            Parameter::parse("*i 1024 r1"),
            Some(p(
                true,
                Int32,
                Some(Source::Int(1024)),
                Some(Destination::Register(1))
            ))
        );
    }

    #[test]
    fn parameter_parse_dest_only() {
        assert_eq!(
            Parameter::parse("t .r0"),
            Some(p(false, TChar, None, Some(Destination::Register(0))))
        );
    }

    #[test]
    fn parameter_parse_compact_source_register() {
        assert_eq!(
            Parameter::parse("pr1"),
            Some(p(false, Pointer, Some(Source::Register(1)), None))
        );
    }

    #[test]
    fn parameter_parse_compact_dest_register() {
        assert_eq!(
            Parameter::parse("t.r2"),
            Some(p(false, TChar, None, Some(Destination::Register(2))))
        );
    }

    #[test]
    fn parameter_parse_compact_source_and_dest() {
        assert_eq!(
            Parameter::parse("*i0s"),
            Some(p(
                true,
                Int32,
                Some(Source::Int(0)),
                Some(Destination::Stack)
            ))
        );
    }

    #[test]
    fn parameter_parse_negative_source() {
        assert_eq!(
            Parameter::parse("p-1"),
            Some(p(false, Pointer, Some(Source::Int(-1)), None))
        );
    }

    #[test]
    fn parameter_parse_type_only() {
        assert_eq!(Parameter::parse("p"), Some(p(false, Pointer, None, None)));
    }

    #[test]
    fn parameter_parse_pointer_type_only() {
        assert_eq!(Parameter::parse("*i"), Some(p(true, Int32, None, None)));
    }

    #[test]
    fn parameter_parse_nsis_variable_source() {
        assert_eq!(
            Parameter::parse("p $HWNDPARENT"),
            Some(p(
                false,
                Pointer,
                Some(Source::Register(
                    Variables::NUM_REGISTERS + PredefinedVar::WindowParent as usize
                )),
                None
            ))
        );
    }

    #[test]
    fn parameter_parse_hex_source_no_dot_split() {
        assert_eq!(
            Parameter::parse("i 0x7FFE"),
            Some(p(false, Int32, Some(Source::Int(0x7FFE)), None))
        );
    }

    #[test]
    fn parameter_parse_struct_type_with_size() {
        assert_eq!(
            Parameter::parse("&t128"),
            Some(p(false, StructTCharArray(128), None, None))
        );
    }

    #[test]
    fn parameter_parse_stack_dest() {
        assert_eq!(
            Parameter::parse("i.s"),
            Some(p(false, Int32, None, Some(Destination::Stack)))
        );
    }
}
