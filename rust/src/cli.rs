use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aws_sdk_cloudformation::types::StackStatus;
use colored::Colorize;
use tokio::time::Duration;

use nitor_vault::{cloudformation, CreateStackResult, Value, Vault};

static WAIT_ANIMATION_DURATION: Duration = Duration::from_millis(500);
static CLEAR_LINE: &str = "\x1b[2K";
static WAIT_DOTS: [&str; 4] = [".", "..", "...", ""];

/// Initialize a new vault stack with Cloudformation and wait for creation to finish.
pub async fn init_vault_stack(
    stack_name: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
) -> Result<()> {
    match Vault::init(stack_name, region, bucket).await? {
        CreateStackResult::Exists { data } => {
            println!("Vault stack already initialized");
            println!("{data}");
        }
        CreateStackResult::ExistsWithFailedState { data } => {
            anyhow::bail!(
                "{}\n{data}",
                "Vault stack exists but is in a failed state".red()
            )
        }
        CreateStackResult::Created {
            stack_name,
            stack_id,
            region,
        } => {
            println!("Stack created with ID: {stack_id}");
            let config = aws_config::from_env().region(region).load().await;
            wait_for_stack_creation_to_finish(&config, &stack_name).await?;
        }
    }
    Ok(())
}

/// Update existing Cloudformation vault stack and wait for update to finish.
pub async fn update_vault_stack(vault: &Vault) -> Result<()> {
    vault
        .update_stack()
        .await
        .with_context(|| "Failed to update vault stack".red())?;

    // TODO: maybe store SdkConfig in vault struct for reuse
    let config = aws_config::from_env()
        .region(vault.region.clone())
        .load()
        .await;

    wait_for_stack_update_to_finish(&config, &vault.cloudformation_params.stack_name).await
}

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

/// Poll Cloudformation for stack status until it has been created or creation failed.
async fn wait_for_stack_creation_to_finish(
    config: &aws_config::SdkConfig,
    stack_name: &str,
) -> Result<()> {
    let client = aws_sdk_cloudformation::Client::new(config);
    let mut last_status: Option<StackStatus> = None;
    loop {
        let stack_data = cloudformation::get_stack_data(&client, stack_name).await?;
        if let Some(ref status) = stack_data.status {
            match status {
                StackStatus::CreateComplete => {
                    println!("{CLEAR_LINE}{stack_data}");
                    println!("{}", "Stack creation completed successfully".green());
                    break;
                }
                StackStatus::CreateFailed
                | StackStatus::RollbackFailed
                | StackStatus::RollbackComplete => {
                    println!("{CLEAR_LINE}{stack_data}");
                    anyhow::bail!("Stack creation failed");
                }
                _ => {
                    // Print status if it has changed
                    if last_status.as_ref() != Some(status) {
                        last_status = Some(status.clone());
                        println!("status: {status}");
                    }
                    // Continue waiting for stack creation to complete
                    for dot in WAIT_DOTS {
                        print!("\r{CLEAR_LINE}{dot}");
                        std::io::stdout().flush()?;
                        tokio::time::sleep(WAIT_ANIMATION_DURATION).await;
                    }
                }
            }
        } else {
            anyhow::bail!("Failed to get stack status for stack '{stack_name}'");
        }
    }
    Ok(())
}

/// Poll Cloudformation for stack status until it has been updated or update failed.
async fn wait_for_stack_update_to_finish(
    config: &aws_config::SdkConfig,
    stack_name: &str,
) -> Result<()> {
    let client = aws_sdk_cloudformation::Client::new(config);
    let mut last_status: Option<StackStatus> = None;
    loop {
        let stack_data = cloudformation::get_stack_data(&client, stack_name).await?;
        if let Some(ref status) = stack_data.status {
            match status {
                StackStatus::UpdateComplete => {
                    println!("{CLEAR_LINE}{stack_data}");
                    println!("{}", "Stack update completed successfully".green());
                    break;
                }
                StackStatus::UpdateFailed | StackStatus::RollbackFailed => {
                    println!("{CLEAR_LINE}{stack_data}");
                    anyhow::bail!("Stack update failed");
                }
                _ => {
                    // Print status if it has changed
                    if last_status.as_ref() != Some(status) {
                        last_status = Some(status.clone());
                        println!("status: {status}");
                    }
                    // Continue waiting for stack update to complete
                    for dot in WAIT_DOTS {
                        print!("\r{CLEAR_LINE}{dot}");
                        std::io::stdout().flush()?;
                        tokio::time::sleep(WAIT_ANIMATION_DURATION).await;
                    }
                }
            }
        } else {
            anyhow::bail!("Failed to get stack status for stack '{stack_name}'");
        }
    }
    Ok(())
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
