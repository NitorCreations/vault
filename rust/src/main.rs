use anyhow::{Context, Result};
use cli::{Args, Command};
use nitor_vault::{CloudFormationParams, Vault};

mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = cli::parse_args().await;

    // Bucket and key were either given as args or found in env variables
    let client = if args.bucket.is_some() && args.key_arn.is_some() {
        Vault::from_params(
            CloudFormationParams::from(args.bucket.as_deref().unwrap(), args.key_arn.as_deref()),
            args.region.as_deref(),
        )
        .await
        .context("Failed to create vault from given params.")?
    } else {
        Vault::new(args.vault_stack.as_deref(), args.region.as_deref())
            .await
            .context("Failed to create vault.")?
    };

    // Handle subcommands
    if let Some(command) = args.command {
        return match command {
            Command::Delete { key } => cli::delete(&client, &key).await,
            Command::Describe {} => Ok(println!("{}", client.stack_info())),
            Command::Exists { key } => cli::exists(&client, key).await,
            Command::All {} => cli::list_all(&client).await,
            Command::Lookup { key } => cli::lookup(&client, &key).await,
            Command::Store {
                key,
                value,
                overwrite,
                file,
                value_opt,
            } => cli::store(&client, key, value, file, value_opt, overwrite).await,
            Command::Info {} => Ok(println!("{}", client.stack_info())),
        };
    }
    Ok(())
}
