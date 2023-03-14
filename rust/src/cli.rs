use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{stdin, BufRead};

use nitor_vault::Vault;

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = "Nitor Vault, see https://github.com/nitorcreations/vault for usage examples",
    subcommand_required = true,
    arg_required_else_help = true
)] // Reads info from `Cargo.toml`
pub struct Args {
    /// List all available secrets
    #[arg(short, long, help = "List available secrets")]
    pub all: bool,

    /// Describe CloudFormation stack parameters
    #[arg(
        long,
        help = "Describe CloudFormation stack parameters for current configuration"
    )]
    pub describestack: bool,

    /// Delete key
    #[arg(short, long, help = "Delete key", value_name = "KEY")]
    pub delete: Option<String>,

    /// Print debug information
    #[arg(long, help = "Print information")]
    pub info: bool,

    /// Print secret value for given key
    #[arg(
        short,
        long,
        help = "Print secret value for given key",
        value_name = "KEY"
    )]
    pub lookup: Option<String>,

    /// Specify AWS region to use
    #[arg(short, long, help = "Specify AWS region for the bucket")]
    pub region: Option<String>,

    /// Available subcommands
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Delete an existing key from the store
    Delete { key: String },

    /// Describe CloudFormation stack parameters for current configuration.
    // This value is useful for Lambdas as you can load the CloudFormation parameters from env.
    DescribeStack {},

    /// Check if a key exists
    Exists { key: String },

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
}

/// Parse command line arguments.
///
/// See Clap `Derive` documentation for details:
/// https://docs.rs/clap/latest/clap/_derive/index.html
pub async fn parse_args() -> Args {
    Args::parse()
}

/// Store key-value pair
pub async fn store(
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

    if !overwrite
        && vault
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

pub async fn delete(vault: &Vault, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!("Empty key '{}'", key)
    }
    vault
        .delete(key)
        .await
        .with_context(|| format!("Error deleting key '{}'.", key))
}

pub async fn lookup(vault: &Vault, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!("Empty key '{}'", key)
    }
    vault
        .lookup(key)
        .await
        .with_context(|| format!("Error looking up key '{}'.", key))
        .map(|res| print!("{res}"))
}

pub async fn list_all(vault: &Vault) -> Result<()> {
    vault
        .all()
        .await
        .with_context(|| "Error listing all keys".to_string())
        .map(|list| println!("{}", list.join("\n")))
}

pub async fn exists(vault: &Vault, key: &str) -> Result<()> {
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
