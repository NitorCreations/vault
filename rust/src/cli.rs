use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;

use nitor_vault::{Value, Vault};

/// Store a key-value pair
pub async fn store(
    vault: &Vault,
    key: Option<String>,
    value_positional: Option<String>,
    file: Option<String>,
    value_argument: Option<String>,
    overwrite: bool,
) -> Result<()> {
    let key = {
        if let Some(key) = key {
            key
        } else if let Some(file_name) = &file {
            if file_name == "-" {
                anyhow::bail!("Key cannot be empty when reading from stdin".red())
            }
            let key = get_filename_from_path(file_name)?;
            println!("Using filename as key: '{key}'");
            key
        } else {
            anyhow::bail!(
                "Empty key and no {} flag provided, provide at least one of these",
                "--file".yellow().bold()
            )
        }
    };

    let value = read_value(value_positional, value_argument, file)?;

    if !overwrite
        && vault
            .exists(&key)
            .await
            .with_context(|| format!("Failed to check if key '{key}' exists").red())?
    {
        anyhow::bail!(
            "Key already exists and no {} flag provided for overwriting",
            "-w".yellow().bold()
        )
    }

    Box::pin(vault.store(&key, value.as_bytes()))
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
pub async fn lookup(vault: &Vault, key: &str, outfile: Option<String>) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!(format!("Empty key '{key}'").red())
    }

    let result = Box::pin(vault.lookup(key))
        .await
        .with_context(|| format!("Failed to look up key '{key}'").red())?;

    match resolve_output_file_path(outfile)? {
        Some(path) => result.output_to_file(&path)?,
        None => result.output_to_stdout()?,
    };

    Ok(())
}

/// List all available keys
pub async fn list_all_keys(vault: &Vault) -> Result<()> {
    vault
        .all()
        .await
        .with_context(|| "Failed to list all keys".red())
        .map(|list| {
            if !list.is_empty() {
                println!("{}", list.join("\n"));
            }
        })
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
        .map(|result| {
            if result {
                println!("key '{key}' exists");
            } else {
                println!("{}", format!("key '{key}' doesn't exist").red());
            }
        })
}

/// Try to get the filename for the given filepath
fn get_filename_from_path(path: &str) -> Result<String> {
    let path = Path::new(path);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", path.display());
    }
    path.file_name()
        .map(|filename| {
            filename
                .to_string_lossy()
                // Remove all U+FFFD replacement characters
                .replace('\u{FFFD}', "")
        })
        .ok_or_else(|| {
            anyhow::anyhow!("No filename found in the provided path: {}", path.display())
        })
}

/// Resolves an optional output file path and creates all directories if necessary.
/// Returns `Some(PathBuf)` if the file path is valid,
/// or `None` if a file path was not provided.
fn resolve_output_file_path(outfile: Option<String>) -> Result<Option<PathBuf>> {
    if let Some(output) = outfile {
        let path = PathBuf::from(output);

        // Ensure all parent directories exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create directories for '{}'", parent.display())
            })?;
        }
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

fn read_value(
    value_positional: Option<String>,
    value_argument: Option<String>,
    file: Option<String>,
) -> Result<Value> {
    Ok(if let Some(value) = value_positional.or(value_argument) {
        if value == "-" {
            Value::from_stdin()?
        } else {
            Value::Utf8(value)
        }
    } else if let Some(path) = file {
        match path.as_str() {
            "-" => Value::from_stdin()?,
            _ => Value::from_path(path)?,
        }
    } else {
        anyhow::bail!("No value or filename provided".red())
    })
}
