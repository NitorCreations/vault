use std::error::Error;

use nitor_vault::Vault;

use clap::Parser;

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = "Nitor Vault, see https://github.com/nitorcreations/vault for usage examples"
)] // Reads info from `Cargo.toml`
struct Args {
    #[arg(short, long, help = "Print secret value for given name")]
    lookup: Option<String>,

    #[arg(short, long, help = "List available secrets")]
    all: bool,

    #[arg(short, long, help = "specify region for the bucket")]
    region: Option<String>,

    #[arg(
        long,
        help = "describe cloudformation stack params for current configuration"
    )]
    describestack: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = parse_args().await;

    let client = Vault::new(None, args.region.as_deref()).await?;

    if let Some(name) = args.lookup.as_deref() {
        print!("{}", client.lookup(name).await.unwrap());
        return Ok(());
    }

    if args.all {
        list_all(&client).await;
        return Ok(());
    }
    if args.describestack {
        println!("{:?}", client.stack_info());
    }

    Ok(())
}

async fn parse_args() -> Args {
    Args::parse()
}

async fn list_all(vault: &Vault) {
    match vault.all().await {
        Ok(all) => println!("{}", all.join("\n")),
        Err(error) => println!("error occurred: {}", error),
    }
}
