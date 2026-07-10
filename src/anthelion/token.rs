use napi::bindgen_prelude::*;
use secrecy::SecretString;

use super::github_configuration;

pub struct GitHubToken {
    token: SecretString,
}

impl GitHubToken {
    fn from_string(token: String) -> Self {
        Self {
            token: SecretString::new(token.into_boxed_str()),
        }
    }
}

impl AsRef<SecretString> for GitHubToken {
    fn as_ref(&self) -> &SecretString {
        &self.token
    }
}

pub fn resolve_github_token(token: Option<&str>) -> napi::Result<GitHubToken> {
    if let Some(env_token) = github_configuration::github_token() {
        return Ok(GitHubToken::from_string(env_token.to_owned()));
    }

    if let Some(token) = token
        && !token.trim().is_empty()
    {
        return Ok(GitHubToken::from_string(token.to_owned()));
    }

    Err(Error::new(
        Status::InvalidArg,
        "No GitHub token provided. Set GITHUB_TOKEN or pass token.",
    ))
}
