mod cli;

use anyhow::{Context, Result};
use colored::Colorize;

use crate::cli::{Args, Command};

use nitor_vault::{CloudFormationParams, Vault};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = cli::parse_args();

    // Bucket and key were either given as args or found in env variables
    let vault = if args.bucket.is_some() && args.key_arn.is_some() {
        Vault::from_params(
            CloudFormationParams::from(args.bucket.as_deref().unwrap(), args.key_arn.as_deref()),
            args.region.as_deref(),
        )
        .await
        // Note: `with_context` is used instead of the simpler `context`
        // as it is lazily evaluated.
        .with_context(|| "Failed to create vault from given params".red())?
    } else {
        Vault::new(args.vault_stack.as_deref(), args.region.as_deref())
            .await
            .with_context(|| "Failed to create vault".red())?
    };

    // Handle subcommands
    if let Some(command) = args.command {
        return match command {
            Command::Delete { key } => cli::delete(&vault, &key).await,
            Command::Describe {} => Ok(println!("{}", vault.stack_info())),
            Command::Exists { key } => cli::exists(&vault, &key).await,
            Command::All {} => cli::list_all(&vault).await,
            Command::Lookup { key } => cli::lookup(&vault, &key).await,
            Command::Store {
                key,
                value,
                overwrite,
                file,
                value_opt,
            } => cli::store(&vault, key, value, file, value_opt, overwrite).await,
            Command::Info {} => Ok(println!("{}", vault)),
        };
    }
    Ok(())
}
