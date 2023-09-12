use anyhow::{Context, Result};
use cli::{Args, Command};
use nitor_vault::Vault;

mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = cli::parse_args().await;

    let client = Vault::new(
        args.vault_stack.as_deref(),
        args.region.as_deref(),
        args.bucket.as_deref(),
        args.key_arn.as_deref(),
    )
    .await
    .with_context(|| "Failed to create vault.".to_string())?;

    // Handle args with no parameters
    if args.all {
        return cli::list_all(&client).await;
    } else if args.describe {
        println!("{}", client.stack_info());
        return Ok(());
    } else if args.info {
        client.test();
        return Ok(());
    }

    if let Some(key) = args.lookup.as_deref() {
        return cli::lookup(&client, key).await;
    }

    // Handle subcommands
    if let Some(command) = &args.command {
        return match command {
            Command::Delete { key } => cli::delete(&client, key).await,
            Command::Describe {} => Ok(println!("{}", client.stack_info())),
            Command::Exists { key } => cli::exists(&client, key).await,
            Command::List {} => cli::list_all(&client).await,
            Command::Load { key } => cli::lookup(&client, key).await,
            Command::Store {
                key,
                value,
                overwrite,
                file,
            } => cli::store(&client, key, value, file, overwrite).await,
        };
    }
    Ok(())
}
