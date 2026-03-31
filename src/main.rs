#[cfg(all(feature = "openssl", feature = "rustls"))]
compile_error!("`openssl` and `rustls` are mutually exclusive. Please enable only one.");

use clap::{Parser, Subcommand, crate_name};
use color_eyre::eyre::Result;
use tracing::metadata::LevelFilter;
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::commands::{
    analyze::Analyze,
    autoupdate::AutoUpdate,
    cleanup::Cleanup,
    compare_installers::CompareInstallers,
    complete::Complete,
    list_versions::ListVersions,
    new_version::NewVersion,
    remove_dead_versions::RemoveDeadVersions,
    remove_version::RemoveVersion,
    show_version::ShowVersion,
    submit::Submit,
    sync_fork::SyncFork,
    token::commands::{TokenArgs, TokenCommands},
    update_version::UpdateVersion,
};

mod analysis;
mod commands;
mod download;
mod download_file;
mod editor;
mod github;
mod manifests;
mod match_installers;
mod prompts;
mod read;
mod terminal;
mod token;
mod traits;
mod update_state;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::config::HookBuilder::default()
        .display_env_section(false)
        .install()?;

    setup_logging();

    match Cli::parse().command {
        Commands::New(new_version) => new_version.run().await,
        Commands::Update(update_version) => update_version.run().await,
        Commands::AutoUpdate(autoupdate) => autoupdate.run().await,
        Commands::Cleanup(cleanup) => cleanup.run().await,
        Commands::Remove(remove_version) => remove_version.run().await,
        Commands::Token(token_args) => match token_args.command {
            TokenCommands::Remove(remove_token) => remove_token.run(),
            TokenCommands::Update(update_token) => update_token.run().await,
        },
        Commands::List(list_versions) => list_versions.run().await,
        Commands::Show(show_version) => show_version.run().await,
        Commands::Sync(sync_fork) => sync_fork.run().await,
        Commands::Complete(complete) => complete.run(),
        Commands::Analyze(analyse) => analyse.run(),
        Commands::CompareInstallers(compare) => compare.run().await,
        Commands::RemoveDeadVersions(remove_dead_versions) => remove_dead_versions.run().await,
        Commands::Submit(submit) => submit.run().await,
    }
}

fn setup_logging() {
    let indicatif_layer = IndicatifLayer::new();
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    // Respect RUST_LOG when provided. Only add a crate directive when no
    // explicit env filter is set.
    let env_filter = if std::env::var_os("RUST_LOG").is_some() {
        env_filter
    } else {
        env_filter.add_directive(format!("{}=info", crate_name!()).parse().unwrap())
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(indicatif_layer.get_stderr_writer())
                .with_target(cfg!(debug_assertions))
                .without_time(),
        )
        .with(indicatif_layer)
        .with(env_filter)
        .init();
}

#[derive(Parser)]
#[command(author, version, about, long_about = None, disable_version_flag = true)]
struct Cli {
    #[arg(short = 'v', short_alias = 'V', long, action = clap::builder::ArgAction::Version)]
    version: (),
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    New(Box<NewVersion>),       // Comparatively large so boxed to store on the heap
    Update(Box<UpdateVersion>), // Comparatively large so boxed to store on the heap
    AutoUpdate(AutoUpdate),
    Remove(RemoveVersion),
    Cleanup(Cleanup),
    Token(TokenArgs),
    List(ListVersions),
    Show(ShowVersion),
    Sync(SyncFork),
    Complete(Complete),
    Analyze(Analyze),
    CompareInstallers(CompareInstallers),
    RemoveDeadVersions(RemoveDeadVersions),
    Submit(Submit),
}
