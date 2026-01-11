use crate::analysis::installers::nsis::state::NsisState;
use tracing::warn;

/// https://nsis.sourceforge.io/System.html
pub fn evaluate(state: &mut NsisState, function_str: &str) {
    match function_str {
        "TestParameter" => {
            state.stack.push(std::borrow::Cow::Borrowed("false").into());
        }
        "GetParentPath" => {
            let path = state.get_string(0);
            let parent = std::path::Path::new(path.as_ref())
                .parent()
                .and_then(|p| p.to_str())
                .unwrap_or("")
                .to_string();
            state
                .stack
                .push(std::borrow::Cow::<str>::Owned(parent).into());
        }
        _ => {
            warn!("Unimplemented function {}", function_str);
        }
    }
}
