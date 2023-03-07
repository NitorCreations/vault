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
        help = "Describe Cloudformation stack params for current configuration"
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
    Store { key: String, value: Vec<u8> },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Args = parse_args().await;

    let client = Vault::new(None, args.region.as_deref())
        .await
        .with_context(|| format!("error creating vault."))?;

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
        Some(Commands::Store { key, value }) => store(&client, key, value).await,
        None => Ok(()),
    }
}

async fn parse_args() -> Args {
    Args::parse()
}

async fn store(vault: &Vault, key: &str, value: &Vec<u8>) -> Result<()> {
    vault
        .store(key, &value)
        .await
        .with_context(|| format!("Error saving key {}", key))
}

async fn lookup(vault: &Vault, key: &str) -> Result<()> {
    vault
        .lookup(key)
        .await
        .with_context(|| format!("Error looking up key {}.", key))
        .map(|res| print!("{res}"))
}
async fn list_all(vault: &Vault) -> Result<()> {
    vault
        .all()
        .await
        .with_context(|| format!("Error listing all keys"))
        .map(|list| println!("{}", list.join("\n")))
}
