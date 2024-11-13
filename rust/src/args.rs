use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use colored::Colorize;

use crate::{cli, Vault};

#[allow(clippy::doc_markdown)]
#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = "Nitor Vault, see https://github.com/nitorcreations/vault for usage examples",
    arg_required_else_help = true
)]
struct Args {
    /// Override the bucket name
    #[arg(short, long, env = "VAULT_BUCKET")]
    bucket: Option<String>,

    /// Override the KMS key ARN
    #[arg(short, long, name = "ARN", env = "VAULT_KEY")]
    key_arn: Option<String>,

    /// Optional prefix for key name
    #[arg(short, long, env = "VAULT_PREFIX")]
    prefix: Option<String>,

    /// Specify AWS region for the bucket
    #[arg(short, long, env = "AWS_REGION")]
    region: Option<String>,

    /// Specify CloudFormation stack name to use
    #[arg(long = "vaultstack", name = "NAME", env = "VAULT_STACK")]
    vault_stack: Option<String>,

    /// Specify AWS profile to use
    #[arg(long = "profile", name = "PROFILE", env = "AWS_PROFILE")]
    aws_profile: Option<String>,

    /// Suppress additional output and error messages
    #[arg(short, long)]
    quiet: bool,

    /// Available subcommands
    #[command(subcommand)]
    command: Option<Command>,
}

#[allow(clippy::doc_markdown)]
#[derive(Subcommand)]
enum Command {
    /// List available secrets
    #[command(
        short_flag('a'),
        long_flag("all"),
        visible_alias("a"),
        visible_alias("list"),
        visible_alias("ls")
    )]
    All {},

    /// Generate shell completion
    #[command(long_flag("completion"))]
    Completion {
        shell: Shell,

        /// Output completion directly to the default directory instead of stdout
        #[arg(short, long, default_value_t = false)]
        install: bool,
    },

    /// Delete an existing key from the store
    #[command(short_flag('d'), long_flag("delete"), visible_alias("d"))]
    Delete {
        /// Key name to delete
        key: String,
    },

    /// Print CloudFormation stack parameters for current configuration.
    // This value is useful for Lambdas as you can load the CloudFormation parameters from env.
    #[command(long_flag("describe"))]
    Describe {},

    /// Directly decrypt given value
    #[command(short_flag('y'), long_flag("decrypt"), visible_alias("y"))]
    Decrypt {
        /// Value to decrypt, use '-' for stdin
        value: Option<String>,

        /// Value to decrypt, use '-' for stdin
        #[arg(
            short,
            long = "value",
            value_name = "value",
            conflicts_with_all = vec!["value", "file"]
        )]
        value_argument: Option<String>,

        /// File to decrypt, use '-' for stdin
        #[arg(
            short,
            long,
            value_name = "filepath",
            conflicts_with_all = vec!["value", "value_argument"]
        )]
        file: Option<String>,

        /// Optional output file
        #[arg(short, long, value_name = "filepath")]
        outfile: Option<String>,
    },

    /// Directly encrypt given value
    #[command(short_flag('e'), long_flag("encrypt"), visible_alias("e"))]
    Encrypt {
        /// Value to encrypt, use '-' for stdin
        value: Option<String>,

        /// Value to encrypt, use '-' for stdin
        #[arg(
            short,
            long = "value",
            value_name = "value",
            conflicts_with_all = vec!["value", "file"]
        )]
        value_argument: Option<String>,

        /// File to encrypt, use '-' for stdin
        #[arg(
            short,
            long,
            value_name = "filepath",
            conflicts_with_all = vec!["value", "value_argument"]
        )]
        file: Option<String>,

        /// Optional output file
        #[arg(short, long, value_name = "filepath")]
        outfile: Option<String>,
    },

    /// Check if a key exists
    #[command(
        long_flag("exists"),
        long_about = "Check if the given key exists.\n\n\
                      Exits with code 0 if the key exists,\n\
                      code 5 if it does *not* exist,\n\
                      and with code 1 for other errors."
    )]
    Exists {
        /// Key name to check
        key: String,
    },

    /// Print vault information
    #[command(long_flag("info"))]
    Info {},

    /// Print AWS user account information
    #[command(long_about = "Print AWS user account information.\n\n\
        Same as calling `aws sts get-caller-identity`,\n\
        but faster than awscli and output is in plain text.")]
    Id {},

    /// Print vault stack information
    #[command(long_flag("status"))]
    Status {},

    /// Initialize a new KMS key and S3 bucket
    #[command(
        short_flag('i'),
        long_flag("init"),
        visible_alias("i"),
        long_about = "Initialize a KMS key and a S3 bucket with roles for reading\n\
                      and writing on a fresh account via CloudFormation.\n\
                      The account used has to have rights to create the resources.\n\n\
                      Usage examples:\n\
                      - `vault init \"vault-name\"`\n\
                      - `vault -i \"vault-name\"`\n\
                      - `vault --vault-stack \"vault-name\" --init`\n\
                      - `VAULT_STACK=\"vault-name\" vault i`"
    )]
    Init {
        /// Vault stack name
        name: Option<String>,
    },

    /// Update the vault CloudFormation stack.
    #[command(
        short_flag('u'),
        long_flag("update"),
        visible_alias("u"),
        long_about = "Update the CloudFormation stack which declares all resources needed by the vault.\n\n\
                      Usage examples:\n\
                      - `vault update`\n\
                      - `vault update \"vault-name\"`\n\
                      - `vault -u \"vault-name\"`\n\
                      - `vault --vault-stack \"vault-name\" --update`\n\
                      - `VAULT_STACK=\"vault-name\" vault u`"
    )]
    Update {
        /// Optional vault stack name
        name: Option<String>,
    },

    /// Output secret value for given key
    #[command(short_flag('l'), long_flag("lookup"), visible_alias("l"))]
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
        visible_alias("s"),
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
        /// Key name to use for stored value
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
            conflicts_with_all = vec!["value", "value_argument"]
        )]
        file: Option<String>,

        /// Overwrite existing key
        #[arg(short = 'w', long)]
        overwrite: bool,
    },
}

/// Run Vault CLI with the given arguments.
///
/// The argument list needs to include the binary name as the first element.
pub async fn run_cli_with_args(mut args: Vec<String>) -> Result<()> {
    // If args are empty, need to manually trigger the help output.
    // `parse_from` does not do it automatically unlike `parse`.
    if args.is_empty() {
        args = vec!["vault".to_string(), "-h".to_string()];
    } else if args.len() == 1 {
        args.push("-h".to_string());
    }
    let args = Args::parse_from(args);
    let quiet = args.quiet;

    // Suppress error output if flag given
    if let Err(error) = run(args).await {
        if quiet {
            std::process::exit(1);
        } else {
            return Err(error);
        }
    }

    Ok(())
}

/// Run Vault CLI.
pub async fn run_cli() -> Result<()> {
    let args = Args::parse();
    let quiet = args.quiet;

    // Suppress error output if flag given
    if let Err(error) = run(args).await {
        if quiet {
            std::process::exit(1);
        } else {
            return Err(error);
        }
    }

    Ok(())
}

#[inline]
#[allow(clippy::match_same_arms)]
#[allow(clippy::too_many_lines)]
async fn run(args: Args) -> Result<()> {
    if let Some(command) = args.command {
        match command {
            Command::Init { name } => {
                cli::init_vault_stack(
                    args.vault_stack.or(name),
                    args.region,
                    args.bucket,
                    args.aws_profile,
                    args.quiet,
                )
                .await
                .with_context(|| "Vault stack initialization failed".red())?;
            }
            Command::Update { name } => {
                let vault = Vault::new(
                    args.vault_stack.or(name),
                    args.region,
                    args.bucket,
                    args.key_arn,
                    args.prefix,
                    args.aws_profile,
                )
                .await
                .with_context(|| "Failed to create vault with given parameters".red())?;

                cli::update_vault_stack(&vault, args.quiet)
                    .await
                    .with_context(|| "Failed to update vault stack".red())?;
            }
            Command::Completion { shell, install } => {
                cli::generate_shell_completion(shell, Args::command(), install, args.quiet)?;
            }
            Command::Id {} => {
                cli::print_aws_account_id(args.region, args.aws_profile, args.quiet).await?;
            }
            // All other commands can use the same single Vault
            Command::All {}
            | Command::Decrypt { .. }
            | Command::Delete { .. }
            | Command::Describe {}
            | Command::Encrypt { .. }
            | Command::Exists { .. }
            | Command::Info {}
            | Command::Lookup { .. }
            | Command::Status {}
            | Command::Store { .. } => {
                let vault = Vault::new(
                    args.vault_stack,
                    args.region,
                    args.bucket,
                    args.key_arn,
                    args.prefix,
                    args.aws_profile,
                )
                .await
                .with_context(|| "Failed to create vault with given parameters".red())?;

                match command {
                    Command::All {} => cli::list_all_keys(&vault).await?,
                    Command::Delete { key } => cli::delete(&vault, &key).await?,
                    Command::Describe {} => println!("{}", vault.stack_info()),
                    Command::Decrypt {
                        value,
                        file,
                        value_argument,
                        outfile,
                    } => cli::decrypt(&vault, value, value_argument, file, outfile).await?,
                    Command::Encrypt {
                        value,
                        file,
                        value_argument,
                        outfile,
                    } => cli::encrypt(&vault, value, value_argument, file, outfile).await?,
                    Command::Exists { key } => {
                        if !cli::exists(&vault, &key, args.quiet).await? {
                            drop(vault);
                            std::process::exit(5);
                        }
                    }
                    Command::Info {} => println!("{vault}"),
                    Command::Status {} => {
                        let status = vault.stack_status().await?;
                        if !args.quiet {
                            println!("{status}");
                        }
                    }
                    Command::Lookup { key, outfile } => cli::lookup(&vault, &key, outfile).await?,
                    Command::Store {
                        key,
                        value,
                        value_argument,
                        file,
                        overwrite,
                    } => {
                        cli::store(
                            &vault,
                            key,
                            value,
                            value_argument,
                            file,
                            overwrite,
                            args.quiet,
                        )
                        .await?;
                    }
                    // These are here again instead of a `_` so that if new commands are added,
                    // there is an error about missing handling for that.
                    Command::Init { .. } => unreachable!(),
                    Command::Update { .. } => unreachable!(),
                    Command::Id { .. } => unreachable!(),
                    Command::Completion { .. } => unreachable!(),
                }
            }
        };
    }
    Ok(())
}
