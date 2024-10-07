mod cli;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;

use nitor_vault::Vault;

#[allow(clippy::doc_markdown)]
#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = "Nitor Vault, see https://github.com/nitorcreations/vault for usage examples",
    arg_required_else_help = true
)]
pub struct Args {
    /// Override the bucket name
    #[arg(short, long, env = "VAULT_BUCKET")]
    pub bucket: Option<String>,

    /// Override the KMS key arn for storing or looking up
    #[arg(short, long, env = "VAULT_KEY")]
    pub key_arn: Option<String>,

    /// Optional prefix for key name
    #[arg(short, long, env = "VAULT_PREFIX")]
    pub prefix: Option<String>,

    /// Specify AWS region for the bucket
    #[arg(short, long, env = "AWS_REGION")]
    pub region: Option<String>,

    /// Optional CloudFormation stack name to lookup key and bucket
    #[arg(long, env)]
    pub vault_stack: Option<String>,

    /// Available subcommands
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[allow(clippy::doc_markdown)]
#[derive(Subcommand)]
pub enum Command {
    /// List available secrets
    #[command(short_flag('a'), long_flag("all"), alias("a"))]
    All {},

    /// Delete an existing key from the store
    #[command(short_flag('d'), long_flag("delete"))]
    Delete { key: String },

    /// Describe CloudFormation stack parameters for current configuration.
    // This value is useful for Lambdas as you can load the CloudFormation parameters from env.
    #[command(long_flag("describe"))]
    Describe {},

    /// Check if a key exists
    #[command(short_flag('e'), long_flag("exists"), alias("e"))]
    Exists { key: String },

    /// Print region and stack information
    #[command(short_flag('i'), long_flag("info"), alias("i"))]
    Info {},

    /// Output secret value for given key
    #[command(short_flag('l'), long_flag("lookup"), alias("l"))]
    Lookup {
        /// Key name to lookup
        key: String,

        /// Optional output file
        #[arg(short, long, value_name = "filepath")]
        outfile: Option<String>,
    },

    /// Store a new key-value pair
    #[command(
        short_flag('s'),
        long_flag("store"),
        alias("s"),
        long_about = "Store a new key-value pair in the vault.\n\
                      You can provide the key and value directly, or specify a file to store.\n\n\
                      Usage examples:\n\
                      - Store a value: `vault store mykey \"some value\"`\n\
                      - Store a value from args: `vault store mykey --value \"some value\"`\n\
                      - Store from a file: `vault store mykey --file path/to/file.txt`\n\
                      - Store from a file with filename as key: `vault store --file path/to/file.txt`\n\
                      - Store from stdin: `echo \"some data\" | vault store mykey --value -`\n\
                      - Store from stdin: `cat file.zip | vault store mykey --file -`"
    )]
    Store {
        /// Key name
        key: Option<String>,

        /// Value to store, use '-' for stdin
        value: Option<String>,

        /// Value to store, use '-' for stdin
        #[arg(
            short,
            long = "value",
            value_name = "value",
            conflicts_with_all = vec!["value", "file"]
        )]
        value_argument: Option<String>,

        /// File to store, use '-' for stdin
        #[arg(
            short,
            long,
            value_name = "filepath",
            conflicts_with_all = vec!["value", "value_opt"]
        )]
        file: Option<String>,

        /// Overwrite existing key
        #[arg(short = 'w', long)]
        overwrite: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let vault = Vault::new(
        args.vault_stack,
        args.region,
        args.bucket,
        args.key_arn,
        args.prefix,
    )
    .await
    .with_context(|| "Failed to create vault from given params".red())?;

    // Handle subcommands
    if let Some(command) = args.command {
        return match command {
            Command::All {} => cli::list_all_keys(&vault).await,
            Command::Delete { key } => cli::delete(&vault, &key).await,
            Command::Describe {} => Ok(println!("{}", vault.stack_info())),
            Command::Exists { key } => cli::exists(&vault, &key).await,
            Command::Info {} => Ok(println!("{vault}")),
            Command::Lookup { key, outfile } => cli::lookup(&vault, &key, outfile).await,
            Command::Store {
                key,
                value,
                overwrite,
                file,
                value_argument,
            } => cli::store(&vault, key, value, file, value_argument, overwrite).await,
        };
    }
    Ok(())
}
