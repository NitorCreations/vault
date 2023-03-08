use std::io::{stdin, BufRead};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nitor_vault::Vault;

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = "Nitor Vault, see https://github.com/nitorcreations/vault for usage examples"
)] // Reads info from `Cargo.toml`
struct Args {
    #[arg(short, long, help = "List available secrets")]
    all: bool,

    #[arg(
        long,
        help = "Describe CloudFormation stack params for current configuration"
    )]
    describestack: bool,

    // TODO
    //#[arg(short, long, help = "Delete key", value_name = "KEY")]
    //delete: Option<String>,
    #[arg(long, help = "Print information")]
    info: bool,

    #[arg(
        short,
        long,
        help = "Print secret value for given key",
        value_name = "KEY"
    )]
    lookup: Option<String>,

    // TODO
    //#[arg(short = 'w', long, help = "Overwrite existing key", value_name = "KEY")]
    //overwrite: Option<String>,
    #[arg(short, long, help = "Specify region for the bucket")]
    region: Option<String>,

    // TODO
    //#[arg(
    //    short,
    //    long,
    //    help = "Updates the CloudFormation stack that declares all resources needed by the vault",
    //    value_name = "KEY"
    //)]
    //update: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// List available secrets
    List {},
    /// Print secret value for given key
    Load { key: String },
    /// Store new key-value pair
    Store {
        key: Option<String>,
        #[arg(short = 'w', long, help = "Overwrite existing key")]
        overwrite: bool,
        value: Option<String>,
        #[arg(
            short,
            long,
            help = "Point to a file that will be stored, - for stdin",
            value_name = "filename",
            conflicts_with = "value"
        )]
        file: Option<String>,
    },
    /// Delete an existing key from the store
    Delete { key: String },
    /// Check if a key exists
    Exists { key: String },
    /// Describe CloudFormation stack params for current configuration.
    /// This value is useful for Lambdas as you can load the CfParams from env rather than from CloudFormation.
    DescribeStack {},
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = parse_args().await;

    let client = Vault::new(None, args.region.as_deref())
        .await
        .with_context(|| "Failed to create vault.".to_string())?;

    if args.all {
        return list_all(&client).await;
    } else if args.describestack {
        println!("{:#?}", client.stack_info());
        return Ok(());
    } else if args.info {
        client.test();
        return Ok(());
    }

    if let Some(key) = args.lookup.as_deref() {
        return lookup(&client, key).await;
    }

    match &args.command {
        Some(Commands::List {}) => list_all(&client).await,
        Some(Commands::Load { key }) => lookup(&client, key).await,
        Some(Commands::Store {
            key,
            value,
            overwrite,
            file,
        }) => store(&client, key, value, file, overwrite).await,
        Some(Commands::Exists { key }) => exists(&client, key).await,
        Some(Commands::DescribeStack {}) => Ok(println!("{:#?}", client.stack_info())),
        Some(Commands::Delete { key }) => delete(&client, key).await,
        None => Ok(()),
    }
}

async fn parse_args() -> Args {
    Args::parse()
}

async fn store(
    vault: &Vault,
    key: &Option<String>,
    value: &Option<String>,
    file: &Option<String>,
    overwrite: &bool,
) -> Result<()> {
    let key = {
        if let Some(key) = key {
            key
        } else if let Some(file_name) = file {
            match file_name.as_str() {
                "-" => anyhow::bail!("Key cannot be empty when reading from stdin"),
                _ => file_name,
            }
        } else {
            anyhow::bail!(
                "Empty key and no \x1b[33m-f\x1b[0m flag provided, provide at least one of these"
            )
        }
    };

    let data = {
        if let Some(value) = value {
            value.to_owned()
        } else if let Some(path) = file {
            match path.as_str() {
                "-" => {
                    println!("Reading from stdin, empty line stops reading");
                    stdin()
                        .lock()
                        .lines()
                        .map(|l| l.unwrap())
                        .take_while(|l| !l.trim().is_empty())
                        .fold(String::new(), |acc, line| acc + &line + "\n")
                }
                _ => std::fs::read_to_string(path)
                    .with_context(|| format!("Error reading file '{path}'"))?,
            }
        } else {
            anyhow::bail!("No value or filename provided")
        }
    };

    if !overwrite && vault
            .exists(key)
            .await
            .with_context(|| format!("Error checking if key {key} exists"))?
    {
        anyhow::bail!(
            "Error saving key, it already exists and you did not provide \x1b[33m-w\x1b[0m flag for overwriting"
        )
    }

    vault
        .store(key, data.as_bytes())
        .await
        .with_context(|| format!("Error saving key {}", key))
}

async fn delete(vault: &Vault, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!("Empty key '{}'", key)
    }
    vault
        .delete(key)
        .await
        .with_context(|| format!("Error deleting key '{}'.", key))
}

async fn lookup(vault: &Vault, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!("Empty key '{}'", key)
    }
    vault
        .lookup(key)
        .await
        .with_context(|| format!("Error looking up key '{}'.", key))
        .map(|res| print!("{res}"))
}

async fn list_all(vault: &Vault) -> Result<()> {
    vault
        .all()
        .await
        .with_context(|| "Error listing all keys".to_string())
        .map(|list| println!("{}", list.join("\n")))
}

async fn exists(vault: &Vault, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!("Empty key '{}'", key)
    }
    vault
        .exists(key)
        .await
        .with_context(|| format!("Error checking if key {key} exists"))
        .map(|result| match result {
            true => println!("key {key} exists"),
            false => println!("key {key} doesn't exist"),
        })
}
