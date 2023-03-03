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
    #[arg(short, long, help = "List available secrets")]
    all: bool,

    #[arg(
        long,
        help = "Describe cloudformation stack params for current configuration"
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
    //#[arg(short, long, help = "Store new key", value_name = "KEY", num_args = 2)]
    //store: Option<String>,

    // TODO
    //#[arg(
    //    short,
    //    long,
    //    help = "Updates the CloudFormation stack that declares all resources needed by the vault",
    //    value_name = "KEY"
    //)]
    //update: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = parse_args().await;

    // how to implement this better
    let client = match Vault::new(None, args.region.as_deref()).await {
        Ok(vault) => vault,
        Err(error) => return Ok(println!("Error creating vault:\n {error}")),
    };
    if args.all {
        list_all(&client).await;
        return Ok(());
    } else if args.describestack {
        println!("{:#?}", client.stack_info());
        return Ok(());
    } else if args.info {
        client.test();
        return Ok(());
    }

    if let Some(name) = args.lookup.as_deref() {
        print!("{}", client.lookup(name).await.unwrap());
        return Ok(());
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
