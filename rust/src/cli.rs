use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use aws_sdk_cloudformation::types::StackStatus;
use clap::Command;
use clap_complete::Shell;
use colored::Colorize;
use tokio::time::Duration;

use nitor_vault::{cloudformation, CreateStackResult, UpdateStackResult, Value, Vault};

static WAIT_ANIMATION_DURATION: Duration = Duration::from_millis(500);
static QUIET_WAIT_DURATION: Duration = Duration::from_secs(1);
static CLEAR_LINE: &str = "\x1b[2K";
static WAIT_DOTS: [&str; 4] = [".", "..", "...", ""];

/// Initialize a new vault stack with Cloudformation and wait for creation to finish.
pub async fn init_vault_stack(
    stack_name: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    quiet: bool,
) -> Result<()> {
    match Vault::init(stack_name, region, bucket).await? {
        CreateStackResult::Exists { data } => {
            if !quiet {
                println!("{}", "Vault stack already initialized:".bold());
                println!("{data}");
            }
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
            if !quiet {
                println!("Stack created with ID: {stack_id}");
            }
            let config = aws_config::from_env().region(region).load().await;
            wait_for_stack_creation_to_finish(&config, &stack_name, quiet).await?;
        }
    }
    Ok(())
}

/// Update existing Cloudformation vault stack and wait for update to finish.
pub async fn update_vault_stack(vault: &Vault, quiet: bool) -> Result<()> {
    match vault
        .update_stack()
        .await
        .with_context(|| "Failed to update vault stack".red())?
    {
        UpdateStackResult::UpToDate { data } => {
            if !quiet {
                println!("{}", "Vault stack is up to date:".bold());
                println!("{data}");
            }
            Ok(())
        }
        UpdateStackResult::Updated {
            stack_id,
            previous_version: current_version,
            new_version,
        } => {
            if !quiet {
                println!(
                    "{}",
                    format!("Updating vault stack from version {current_version} to {new_version}")
                        .bold()
                );
                println!("{stack_id}");
            }
            wait_for_stack_update_to_finish(vault, quiet).await
        }
    }
}

/// Store a key-value pair.
pub async fn store(
    vault: &Vault,
    key: Option<String>,
    value_positional: Option<String>,
    file: Option<String>,
    value_argument: Option<String>,
    overwrite: bool,
    quiet: bool,
) -> Result<()> {
    let key = {
        if let Some(key) = key {
            key
        } else if let Some(file_name) = &file {
            if file_name == "-" {
                anyhow::bail!("Key cannot be empty when reading from stdin".red())
            }
            let key = get_filename_from_path(file_name)?;
            if !quiet {
                println!("Using filename as key: '{key}'");
            }
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

/// Delete key value.
pub async fn delete(vault: &Vault, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        anyhow::bail!(format!("Empty key '{key}'").red())
    }
    vault
        .delete(key)
        .await
        .with_context(|| format!("Failed to delete key '{key}'").red())
}

/// Get key value.
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

/// List all available keys.
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

/// Check if key exists.
pub async fn exists(vault: &Vault, key: &str, quiet: bool) -> Result<bool> {
    if key.trim().is_empty() {
        anyhow::bail!(format!("Empty key: '{key}'").red())
    }

    let exists = vault
        .exists(key)
        .await
        .with_context(|| format!("Failed to check if key '{key}' exists").red())?;

    if !quiet {
        if exists {
            println!("key '{key}' exists");
        } else {
            println!("{}", format!("key '{key}' does not exist").red());
        }
    }

    Ok(exists)
}

/// Directly encrypt given value with KMS.
///
/// Always encode resulting binary data as Base64.
pub async fn encrypt(
    vault: &Vault,
    value_positional: Option<String>,
    file: Option<String>,
    value_argument: Option<String>,
    outfile: Option<String>,
) -> Result<()> {
    let data = read_value(value_positional, value_argument, file)?;
    let bytes = vault.direct_encrypt(data.as_bytes()).await?;
    let value = Value::new(bytes).encode_base64();

    match resolve_output_file_path(outfile)? {
        Some(path) => value.output_to_file(&path)?,
        None => value.output_to_stdout()?,
    };

    Ok(())
}

/// Directly decrypt given value with KMS.
///
/// Assumes input data is base64 encoded.
pub async fn decrypt(
    vault: &Vault,
    value_positional: Option<String>,
    file: Option<String>,
    value_argument: Option<String>,
    outfile: Option<String>,
) -> Result<()> {
    let data = read_value(value_positional, value_argument, file)?.decode_base64();
    let bytes = vault.direct_decrypt(data.as_bytes()).await?;
    let value = Value::new(bytes);

    match resolve_output_file_path(outfile)? {
        Some(path) => value.output_to_file(&path)?,
        None => value.output_to_stdout()?,
    };

    Ok(())
}

/// Print the information from AWS STS "get caller identity" call.
pub async fn print_aws_account(region: Option<String>) -> Result<()> {
    let config = Vault::get_aws_config(region).await;
    let client = aws_sdk_sts::Client::new(&config);
    let result = client.get_caller_identity().send().await?;
    println!(
        "user: {}\naccount: {}\narn: {}",
        result.user_id.unwrap_or_else(|| "None".to_string()),
        result.account.unwrap_or_else(|| "None".to_string()),
        result.arn.unwrap_or_else(|| "None".to_string())
    );
    Ok(())
}

/// Poll Cloudformation for stack status until it has been created or creation failed.
async fn wait_for_stack_creation_to_finish(
    config: &aws_config::SdkConfig,
    stack_name: &str,
    quiet: bool,
) -> Result<()> {
    let client = aws_sdk_cloudformation::Client::new(config);
    let mut last_status: Option<StackStatus> = None;
    loop {
        let stack_data = cloudformation::get_stack_data(&client, stack_name).await?;
        if let Some(ref status) = stack_data.status {
            match status {
                StackStatus::CreateComplete => {
                    if !quiet {
                        println!("{CLEAR_LINE}{stack_data}");
                        println!("{}", "Stack creation completed successfully".green());
                    }
                    break;
                }
                StackStatus::CreateFailed
                | StackStatus::RollbackFailed
                | StackStatus::RollbackComplete => {
                    if !quiet {
                        println!("{CLEAR_LINE}{stack_data}");
                    }
                    anyhow::bail!("Stack creation failed");
                }
                _ => {
                    if quiet {
                        tokio::time::sleep(QUIET_WAIT_DURATION).await;
                    } else {
                        // Print status if it has changed
                        if last_status.as_ref() != Some(status) {
                            last_status = Some(status.clone());
                            println!("status: {status}");
                        }
                        // Continue waiting for stack creation to complete
                        print_wait_animation().await?;
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
async fn wait_for_stack_update_to_finish(vault: &Vault, quiet: bool) -> Result<()> {
    let mut last_status: Option<StackStatus> = None;
    loop {
        let stack_data = vault.stack_status().await?;
        if let Some(ref status) = stack_data.status {
            match status {
                StackStatus::UpdateComplete => {
                    if !quiet {
                        println!("{CLEAR_LINE}{stack_data}");
                        println!("{}", "Stack update completed successfully".green());
                    }
                    break;
                }
                StackStatus::UpdateFailed | StackStatus::RollbackFailed => {
                    if !quiet {
                        println!("{CLEAR_LINE}{stack_data}");
                    }
                    anyhow::bail!("Stack update failed".red());
                }
                _ => {
                    if quiet {
                        tokio::time::sleep(QUIET_WAIT_DURATION).await;
                    } else {
                        // Print status if it has changed
                        if last_status.as_ref() != Some(status) {
                            last_status = Some(status.clone());
                            println!("status: {status}");
                        }
                        // Continue waiting for stack update to complete
                        print_wait_animation().await?;
                    }
                }
            }
        } else {
            anyhow::bail!(
                "Failed to get stack status for stack '{}'",
                vault.cloudformation_params.stack_name
            );
        }
    }
    Ok(())
}

/// Generate a shell completion script for the given shell.
pub fn generate_shell_completion(
    shell: Shell,
    mut command: Command,
    install: bool,
    quiet: bool,
) -> Result<()> {
    if install {
        let out_dir = get_shell_completion_dir(shell)?;
        let path = clap_complete::generate_to(shell, &mut command, "vault", out_dir)?;
        if !quiet {
            println!("Completion file generated to: {}", path.display());
        }
    } else {
        clap_complete::generate(shell, &mut command, "vault", &mut std::io::stdout());
    }

    Ok(())
}

/// Try to get the filename for the given filepath.
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

/// Read value depending on given CLI arguments.
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

/// Print simple wait animation with dots.
///
/// Takes ~2 seconds (`4 * WAIT_ANIMATION_DURATION`)
async fn print_wait_animation() -> Result<()> {
    for dot in WAIT_DOTS {
        print!("\r{CLEAR_LINE}{dot}");
        std::io::stdout().flush()?;
        tokio::time::sleep(WAIT_ANIMATION_DURATION).await;
    }
    Ok(())
}

/// Determine the appropriate directory for storing shell completions.
///
/// First checks if the user-specific directory exists,
/// then checks for the global directory.
/// If neither exist, creates and uses the user-specific dir.
fn get_shell_completion_dir(shell: Shell) -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Failed to get home directory"))?;

    // Special handling for oh-my-zsh: https://ohmyz.sh/
    // Create custom "plugin", which will then have to be loaded in .zshrc
    if shell == Shell::Zsh {
        let omz_plugins = home.join(".oh-my-zsh/custom/plugins");
        if omz_plugins.exists() {
            let plugin_dir = omz_plugins.join("vault");
            std::fs::create_dir_all(&plugin_dir)?;
            return Ok(plugin_dir);
        }
    }

    let user_dir = match shell {
        Shell::PowerShell => {
            if cfg!(windows) {
                home.join(r"Documents\PowerShell\completions")
            } else {
                home.join(".config/powershell/completions")
            }
        }
        Shell::Bash => home.join(".bash_completion.d"),
        Shell::Elvish => home.join(".elvish"),
        Shell::Fish => home.join(".config/fish/completions"),
        Shell::Zsh => home.join(".zsh/completions"),
        _ => anyhow::bail!("Unsupported shell"),
    };

    if user_dir.exists() {
        return Ok(user_dir);
    }

    let global_dir = match shell {
        Shell::PowerShell => {
            if cfg!(windows) {
                home.join(r"Documents\PowerShell\completions")
            } else {
                home.join(".config/powershell/completions")
            }
        }
        Shell::Bash => PathBuf::from("/etc/bash_completion.d"),
        Shell::Fish => PathBuf::from("/usr/share/fish/completions"),
        Shell::Zsh => PathBuf::from("/usr/share/zsh/site-functions"),
        _ => anyhow::bail!("Unsupported shell"),
    };

    if global_dir.exists() {
        return Ok(global_dir);
    }

    std::fs::create_dir_all(&user_dir)?;
    Ok(user_dir)
}
