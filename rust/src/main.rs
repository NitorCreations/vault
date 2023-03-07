use std::error::Error;

use nitor_vault::Vault;

use clap::{Parser, Subcommand};

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
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = parse_args().await;

    // how to implement this better
    let client = Vault::new(None, args.region.as_deref()).await?;
    if args.all {
        list_all(&client).await?;
        return Ok(());
    } else if args.describestack {
        println!("{:#?}", client.stack_info());
        return Ok(());
    } else if args.info {
        client.test();
        return Ok(());
    }

    if let Some(name) = args.lookup.as_deref() {
        print!("{}", client.lookup(name).await?);
        return Ok(());
    }

    match &args.command {
        Some(Commands::List {}) => {
            list_all(&client).await?;
            Ok(())
        }
        Some(Commands::Load { key }) => {
            print!("{}", client.lookup(key).await?);
            Ok(())
        }
        Some(Commands::Store { key, value }) => {
            client.store(key, value).await?;
            Ok(())
        }
        None => Ok(()),
    }
}

async fn parse_args() -> Args {
    Args::parse()
}

async fn list_all(vault: &Vault) -> Result<(), nitor_vault::errors::VaultError> {
    Ok(println!("{}", vault.all().await?.join("\n")))
}
