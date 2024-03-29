use std::io::{stdin, BufRead};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;

use nitor_vault::Vault;

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = "Nitor Vault, see https://github.com/nitorcreations/vault for usage examples",
    arg_required_else_help = true
)] // Reads info from `Cargo.toml`
pub struct Args {
    /// Override the bucket name
    #[arg(short, long, env = "VAULT_BUCKET")]
    pub bucket: Option<String>,

    /// Override the KMS key arn for storing or looking up
    #[arg(short, long, env = "VAULT_KEY")]
    pub key_arn: Option<String>,

    /// Specify AWS region for the bucket
    #[arg(short, long, env = "AWS_REGION")]
    pub region: Option<String>,

    /// Optional CloudFormation stack to lookup key and bucket
    #[arg(long, env)]
    pub vault_stack: Option<String>,

    /// Available subcommands
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
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

    /// List available secrets
    #[command(short_flag('a'), long_flag("all"), alias("a"))]
    All {},

    /// Print secret value for given key
    #[command(short_flag('l'), long_flag("lookup"), alias("l"))]
    Lookup { key: String },

    /// Store a new key-value pair
    #[command(short_flag('s'), long_flag("store"), alias("s"))]
    Store {
        key: Option<String>,
        #[arg(short = 'w', long, help = "Overwrite existing key")]
        overwrite: bool,
        #[arg(
            short,
            long,
            help = "Point to a file that will be stored, - for stdin",
            value_name = "value",
            conflicts_with_all = vec!["value","file"]
        )]
        value_opt: Option<String>,
        value: Option<String>,
        #[arg(
            short,
            long,
            help = "Point to a file that will be stored, - for stdin",
            value_name = "filename",
            conflicts_with_all = vec!["value","value_opt"]
        )]
        file: Option<String>,
    },
    /// Print region and stack information
    #[command(short_flag('i'), long_flag("info"), alias("i"))]
    Info {},
}

/// Parse command line arguments.
///
/// See Clap `Derive` documentation for details:
/// https://docs.rs/clap/latest/clap/_derive/index.html
pub fn parse_args() -> Args {
    Args::parse()
}

/// Store key-value pair
pub async fn store(
    vault: &Vault,
    key: Option<String>,
    value: Option<String>,
    file: Option<String>,
    value_opt: Option<String>,
    overwrite: bool,
) -> Result<()> {
    let key = {
        if let Some(key) = &key {
            key
        } else if let Some(file_name) = &file {
            match file_name.as_str() {
                "-" => anyhow::bail!("Key cannot be empty when reading from stdin".red()),
                _ => file_name,
            }
        } else {
            anyhow::bail!(
                "Empty key and no {} flag provided, provide at least one of these",
                "-f".yellow().bold()
            )
        }
    };

    let data = {
        if let Some(value) = value.or(value_opt) {
            value.to_owned()
        } else if let Some(path) = &file {
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
                    .with_context(|| format!("Error reading file: '{path}'").red())?,
            }
        } else {
            anyhow::bail!("No value or filename provided".red())
        }
    };

    if !overwrite
        && vault
            .exists(key)
            .await
            .with_context(|| format!("Failed to check if key '{key}' exists").red())?
    {
        anyhow::bail!(
            "Key already exists and no {} flag provided for overwriting",
            "-w".yellow().bold()
        )
    }

    vault
        .store(key, data.as_bytes())
        .await
        .with_context(|| format!("Failed to store key '{key}'").red())
}

/// Delete key value
pub async fn delete(vault: &Vault, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!(format!("Empty key '{key}'").red())
    }
    vault
        .delete(key)
        .await
        .with_context(|| format!("Failed to delete key '{key}'").red())
}

/// Get key value
pub async fn lookup(vault: &Vault, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!(format!("Empty key '{key}'").red())
    }
    vault
        .lookup(key)
        .await
        .with_context(|| format!("Failed to look up key '{key}'").red())
        .map(|res| print!("{res}"))
}

/// List all available keys
pub async fn list_all(vault: &Vault) -> Result<()> {
    vault
        .all()
        .await
        .with_context(|| "Failed to list all keys".red())
        .map(|list| println!("{}", list.join("\n")))
}

/// Check if key exists
pub async fn exists(vault: &Vault, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!(format!("Empty key: '{key}'").red())
    }
    vault
        .exists(key)
        .await
        .with_context(|| format!("Failed to check if key '{key}' exists").red())
        .map(|result| match result {
            true => println!("key '{key}' exists"),
            false => println!("{}", format!("key '{key}' doesn't exist").red()),
        })
}
