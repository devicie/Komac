use std::sync::OnceLock;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::github::{MICROSOFT, WINGET_PKGS};

static CONFIG: OnceLock<Config> = OnceLock::new();

struct Config {
    github_token: Option<String>,
    dry_run: Option<bool>,
}

impl Config {
    fn get() -> &'static Self {
        CONFIG.get_or_init(|| Self {
            github_token: None,
            dry_run: None,
        })
    }
}

pub fn github_token() -> Option<&'static str> {
    Config::get().github_token.as_deref()
}

pub fn dry_run() -> Option<bool> {
    Config::get().dry_run
}

fn get_env(env: &Object, name: &str) -> napi::Result<Option<String>> {
    Ok(env
        .get_named_property::<Option<String>>(name)?
        .filter(|value| !value.trim().is_empty()))
}

/// Copies configuration from Node's `process.env` into the native binding.
#[napi(module_exports)]
pub fn configure(env: Env) -> napi::Result<()> {
    let process: Object = env.get_global()?.get_named_property("process")?;
    let process_env: Object = process.get_named_property("env")?;

    if let Some(owner) = get_env(&process_env, "KOMAC_GITHUB_OWNER")? {
        MICROSOFT.set(owner);
    }
    if let Some(repo) = get_env(&process_env, "KOMAC_GITHUB_REPO")? {
        WINGET_PKGS.set(repo);
    }

    let dry_run = get_env(&process_env, "DRY_RUN")?
        .map(|value| value.parse())
        .transpose()
        .map_err(|_| Error::new(Status::InvalidArg, "DRY_RUN must be true or false"))?;

    let _ = CONFIG.set(Config {
        github_token: get_env(&process_env, "GITHUB_TOKEN")?,
        dry_run,
    });

    Ok(())
}
