use clap::Parser;
use clap_complete::Shell;
use color_eyre::{Result, Section, eyre::eyre};

/// Outputs an autocompletion script for the given shell. Example usage:
///
/// Bash: echo "source <(komac complete bash)" >> ~/.bashrc
/// Elvish: echo "eval (komac complete elvish | slurp)" >> ~/.elvish/rc.elv
/// Fish: echo "source (komac complete fish | psub)" >> ~/.config/fish/config.fish
/// PowerShell: echo "komac complete powershell | Out-String | Invoke-Expression" >> $PROFILE
/// Zsh: echo "source <(komac complete zsh)" >> ~/.zshrc
#[derive(Parser)]
#[clap(visible_alias = "autocomplete", verbatim_doc_comment)]
pub struct Complete {
    /// Specifies the shell for which to generate the completion script.
    ///
    /// If not provided, the shell will be inferred based on the current environment.
    #[arg()]
    shell: Option<Shell>,
}

impl Complete {
    /// Generate shell completions.
    ///
    /// When invoked from the binary, the caller should provide a closure that
    /// generates completions for the given shell (since the `Cli` type is only
    /// available in `main.rs`).
    pub fn run_with<F>(self, generate_fn: F) -> Result<()>
    where
        F: FnOnce(Shell),
    {
        let Some(shell) = self.shell.or_else(Shell::from_env) else {
            return Err(
                eyre!("Unable to determine the current shell from the environment")
                    .suggestion("Specify shell explicitly"),
            );
        };

        generate_fn(shell);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn run() -> Result<()> {
        Err(eyre!(
            "Completion generation is not available in library mode"
        ))
    }
}
