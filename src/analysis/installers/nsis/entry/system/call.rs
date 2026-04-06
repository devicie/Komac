use super::ResolvedCall;
use crate::analysis::installers::nsis::state::NsisState;

pub(super) trait Call {
    fn call(&mut self, state: &mut NsisState, call: &ResolvedCall<'_>) -> bool;
}
