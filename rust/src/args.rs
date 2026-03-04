//! Specifies CLI arguments and commands
//!

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use colored::Colorize;

use crate::{Vault, cli};

#[allow(clippy::doc_markdown)]
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "Nitor Vault, see https://github.com/nitorcreations/vault for usage examples",
    arg_required_else_help = true
)]
struct Args {
    /// Override the bucket name
    #[arg(short, long, env = "VAULT_BUCKET", global = true)]
    bucket: Option<String>,

    /// Override the KMS key ARN
    #[arg(short, long, name = "ARN", env = "VAULT_KEY", global = true)]
    key_arn: Option<String>,

    /// Optional prefix for key name
    #[arg(short, long, env = "VAULT_PREFIX", global = true)]
    prefix: Option<String>,

    /// Specify AWS region for the bucket
    #[arg(short, long, env = "AWS_REGION", global = true)]
    region: Option<String>,

    /// Specify CloudFormation stack name to use
    #[arg(long = "vaultstack", name = "NAME", env = "VAULT_STACK", global = true)]
    vault_stack: Option<String>,

    /// Specify AWS IAM access key ID
    #[arg(long = "id", name = "ID", requires = "SECRET", global = true)]
    iam_id: Option<String>,

    /// Specify AWS IAM secret access key
    #[arg(long = "secret", name = "SECRET", requires = "ID", global = true)]
    iam_secret: Option<String>,

    /// Specify AWS profile name to use
    #[arg(long = "profile", name = "PROFILE", env = "AWS_PROFILE", global = true)]
    aws_profile: Option<String>,

    /// Suppress additional output and error messages
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Available subcommands
    #[command(subcommand)]
    command: Option<Command>,
}

#[allow(clippy::doc_markdown)]
#[derive(Subcommand, Debug, PartialEq)]
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

    /// Generate shell completions
    ///
    /// Usage examples:
    /// - `vault completion --install zsh`
    /// - `vault completion zsh > "$HOME/.oh-my-zsh/custom/plugins/vault/_vault"`
    /// - `vault --completion bash`
    #[command(long_flag("completion"), verbatim_doc_comment)]
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

    /// Check if a key exists.
    ///
    /// Exits with code 0 if the key exists,
    /// code 5 if it does *not* exist
    /// and with code 1 for other errors.
    #[command(long_flag("exists"))]
    Exists {
        /// Key name to check
        key: String,
    },

    /// Print vault information
    #[command(long_flag("info"))]
    Info {},

    /// Print AWS user account information.
    ///
    /// Same as calling `aws sts get-caller-identity`,
    /// but faster than awscli and output is in plain text.
    #[command()]
    Id {},

    /// Commands for cloudformation stack.
    ///
    /// No subcommand prints vault stack information.
    #[command()]
    Stack {
        #[command(subcommand)]
        action: Option<StackAction>,
    },

    /// Initialize a new KMS key and S3 bucket.
    ///
    /// Initialize a KMS key and a S3 bucket with roles for reading
    /// and writing on a fresh account via CloudFormation.
    /// The account used must have permissions to create these resources.
    ///
    /// Usage examples:
    /// - `vault init "vault-name"`
    /// - `vault -i "vault-name"`
    /// - `vault --vault-stack "vault-name" --init"`
    /// - `VAULT_STACK="vault-name" vault i`
    #[command(
        short_flag('i'),
        long_flag("init"),
        visible_alias("i"),
        verbatim_doc_comment
    )]
    Init {
        /// Vault stack name
        name: Option<String>,
    },

    /// Output secret value for given key
    ///
    /// Note that for binary secret data, the raw bytes will be outputted as is.
    #[command(short_flag('l'), long_flag("lookup"), visible_alias("l"))]
    Lookup {
        /// Key name to lookup
        key: String,

        /// Optional output file
        #[arg(short, long, value_name = "filepath")]
        outfile: Option<String>,
    },

    /// Store a new key-value pair.
    ///
    /// You can provide the key and value directly, or specify a file to store the contents.
    ///
    /// Usage examples:
    /// - Store a value: `vault store "key" "some value"`
    /// - Store a value from args: `vault store "key" --value "some value"`
    /// - Store from a file: `vault store "key" --file "path/to/file.txt"`
    /// - Store from a file with filename as key: `vault store --file "path/to/file.txt"`
    /// - Store from stdin: `echo "some data" | vault store "key" --value -`
    /// - Store from stdin: `cat file.zip | vault store "key" --file -`
    #[command(
        short_flag('s'),
        long_flag("store"),
        visible_alias("s"),
        verbatim_doc_comment
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

    /// Update the vault CloudFormation stack.
    ///
    /// The CloudFormation stack declares all resources needed by the vault.
    ///
    /// Usage examples:
    /// - `vault update`
    /// - `vault update "vault-name"`
    /// - `vault -u "vault-name"`
    /// - `vault --vault-stack "vault-name" --update`
    /// - `VAULT_STACK="vault-name" vault u`
    #[command(
        short_flag('u'),
        long_flag("update"),
        visible_alias("u"),
        verbatim_doc_comment
    )]
    Update {
        /// Optional vault stack name
        name: Option<String>,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum StackAction {
    #[command(
        short_flag('l'),
        long_flag("list"),
        visible_alias("l"),
        visible_alias("ls")
    )]
    /// List all vault stacks
    List,

    /// Delete vault stack
    #[command(long_flag("delete"))]
    Delete {
        /// Vault name
        name: Option<String>,

        /// Vault name
        #[arg(
            short,
            long = "name",
            value_name = "vault",
            conflicts_with_all = vec!["name"]
        )]
        name_argument: Option<String>,

        /// Do not ask for confirmation
        #[arg(short, long)]
        force: bool,
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
                    args.iam_id,
                    args.iam_secret,
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
                    args.iam_id,
                    args.iam_secret,
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
            Command::Stack { action } => match action {
                Some(StackAction::Delete {
                    name,
                    name_argument,
                    force,
                }) => {
                    cli::delete_stack(
                        args.region,
                        args.aws_profile,
                        args.vault_stack.or_else(|| name_argument.or(name)),
                        force,
                        args.quiet,
                    )
                    .await?;
                }
                Some(StackAction::List) => {
                    cli::list_stacks(args.region, args.aws_profile, args.quiet).await?;
                }
                None => {
                    let vault = Vault::new(
                        args.vault_stack,
                        args.region,
                        args.bucket,
                        args.key_arn,
                        args.prefix,
                        args.aws_profile,
                        args.iam_id,
                        args.iam_secret,
                    )
                    .await
                    .with_context(|| "Failed to create vault with given parameters".red())?;
                    let status = vault.stack_status().await?;
                    if !args.quiet {
                        println!("{status}");
                    }
                }
            },
            // All other commands can use the same single Vault
            Command::All {}
            | Command::Decrypt { .. }
            | Command::Delete { .. }
            | Command::Describe {}
            | Command::Encrypt { .. }
            | Command::Exists { .. }
            | Command::Info {}
            | Command::Lookup { .. }
            | Command::Store { .. } => {
                let vault = Vault::new(
                    args.vault_stack,
                    args.region,
                    args.bucket,
                    args.key_arn,
                    args.prefix,
                    args.aws_profile,
                    args.iam_id,
                    args.iam_secret,
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
                    _ => unreachable!(),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Helper to parse args from a string slice
    fn parse_args(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(args)
    }

    // ==================== Global Args Tests ====================

    #[test]
    fn test_global_args_before_subcommand() {
        // Traditional: global args before subcommand
        let args = parse_args(&["vault", "-r", "eu-central-1", "-b", "my-bucket", "--all"])
            .expect("Should parse successfully");

        assert_eq!(args.region, Some("eu-central-1".to_string()));
        assert_eq!(args.bucket, Some("my-bucket".to_string()));
        assert!(matches!(args.command, Some(Command::All {})));
    }

    #[test]
    fn test_global_args_after_subcommand() {
        // New behavior: global args after subcommand should work
        let args = parse_args(&["vault", "--all", "-r", "eu-central-1", "-b", "my-bucket"])
            .expect("Should parse successfully");

        assert_eq!(args.region, Some("eu-central-1".to_string()));
        assert_eq!(args.bucket, Some("my-bucket".to_string()));
        assert!(matches!(args.command, Some(Command::All {})));
    }

    #[test]
    fn test_global_args_mixed_position() {
        // Global args both before and after subcommand
        let args = parse_args(&[
            "vault",
            "-r",
            "eu-central-1",
            "store",
            "mykey",
            "myvalue",
            "-w",
            "-b",
            "my-bucket",
        ])
        .expect("Should parse successfully");

        assert_eq!(args.region, Some("eu-central-1".to_string()));
        assert_eq!(args.bucket, Some("my-bucket".to_string()));
        assert!(matches!(
            args.command,
            Some(Command::Store {
                key: Some(_),
                value: Some(_),
                overwrite: true,
                ..
            })
        ));
    }

    #[test]
    fn test_example_from_user_story() {
        // The exact example from the user: vault -s version.txt -f version.txt -w -r eu-central-1
        // This is store with file flag
        let args = parse_args(&[
            "vault",
            "-s",
            "version.txt",
            "-f",
            "version.txt",
            "-w",
            "-r",
            "eu-central-1",
        ])
        .expect("Should parse successfully");

        assert_eq!(args.region, Some("eu-central-1".to_string()));
        if let Some(Command::Store {
            key,
            file,
            overwrite,
            ..
        }) = args.command
        {
            assert_eq!(key, Some("version.txt".to_string()));
            assert_eq!(file, Some("version.txt".to_string()));
            assert!(overwrite);
        } else {
            panic!("Expected Store command");
        }
    }

    #[test]
    fn test_all_global_args() {
        let args = parse_args(&[
            "vault",
            "-b",
            "test-bucket",
            "-k",
            "arn:aws:kms:region:account:key/id",
            "-p",
            "myprefix",
            "-r",
            "us-west-2",
            "--vaultstack",
            "my-stack",
            "--id",
            "AKIAIOSFODNN7EXAMPLE",
            "--secret",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "--profile",
            "myprofile",
            "-q",
            "--all",
        ])
        .expect("Should parse successfully");

        assert_eq!(args.bucket, Some("test-bucket".to_string()));
        assert_eq!(
            args.key_arn,
            Some("arn:aws:kms:region:account:key/id".to_string())
        );
        assert_eq!(args.prefix, Some("myprefix".to_string()));
        assert_eq!(args.region, Some("us-west-2".to_string()));
        assert_eq!(args.vault_stack, Some("my-stack".to_string()));
        assert_eq!(args.iam_id, Some("AKIAIOSFODNN7EXAMPLE".to_string()));
        assert_eq!(
            args.iam_secret,
            Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string())
        );
        assert_eq!(args.aws_profile, Some("myprofile".to_string()));
        assert!(args.quiet);
        assert!(matches!(args.command, Some(Command::All {})));
    }

    #[test]
    fn test_iam_credentials_require_both() {
        // Only id without secret should fail
        let result = parse_args(&["vault", "--id", "AKIAIOSFODNN7EXAMPLE", "--all"]);
        assert!(result.is_err());

        // Only secret without id should fail
        let result = parse_args(&[
            "vault",
            "--secret",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "--all",
        ]);
        assert!(result.is_err());

        // Both together should succeed
        let result = parse_args(&[
            "vault",
            "--id",
            "AKIAIOSFODNN7EXAMPLE",
            "--secret",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "--all",
        ]);
        assert!(result.is_ok());
    }

    // ==================== Command Tests ====================

    #[test]
    fn test_all_command_variants() {
        // Test all the different ways to invoke "all" command
        let variants = ["-a", "--all", "all", "a", "list", "ls"];
        for variant in variants {
            let args = parse_args(&["vault", variant])
                .unwrap_or_else(|_| panic!("Should parse '{variant}'"));
            assert!(
                matches!(args.command, Some(Command::All {})),
                "Failed for variant: {variant}"
            );
        }
    }

    #[test]
    fn test_store_command_with_key_value() {
        let args =
            parse_args(&["vault", "store", "mykey", "myvalue"]).expect("Should parse successfully");

        if let Some(Command::Store { key, value, .. }) = args.command {
            assert_eq!(key, Some("mykey".to_string()));
            assert_eq!(value, Some("myvalue".to_string()));
        } else {
            panic!("Expected Store command");
        }
    }

    #[test]
    fn test_store_command_short_flag() {
        let args =
            parse_args(&["vault", "-s", "mykey", "myvalue"]).expect("Should parse successfully");

        assert!(matches!(args.command, Some(Command::Store { .. })));
    }

    #[test]
    fn test_store_command_long_flag() {
        let args = parse_args(&["vault", "--store", "mykey", "myvalue"])
            .expect("Should parse successfully");

        assert!(matches!(args.command, Some(Command::Store { .. })));
    }

    #[test]
    fn test_store_command_with_file() {
        let args = parse_args(&["vault", "store", "mykey", "--file", "path/to/file.txt"])
            .expect("Should parse successfully");

        if let Some(Command::Store { key, file, .. }) = args.command {
            assert_eq!(key, Some("mykey".to_string()));
            assert_eq!(file, Some("path/to/file.txt".to_string()));
        } else {
            panic!("Expected Store command");
        }
    }

    #[test]
    fn test_store_command_with_overwrite() {
        let args = parse_args(&["vault", "store", "mykey", "myvalue", "-w"])
            .expect("Should parse successfully");

        if let Some(Command::Store { overwrite, .. }) = args.command {
            assert!(overwrite);
        } else {
            panic!("Expected Store command");
        }
    }

    #[test]
    fn test_lookup_command() {
        let args = parse_args(&["vault", "lookup", "mykey"]).expect("Should parse successfully");

        if let Some(Command::Lookup { key, outfile }) = args.command {
            assert_eq!(key, "mykey");
            assert_eq!(outfile, None);
        } else {
            panic!("Expected Lookup command");
        }
    }

    #[test]
    fn test_lookup_command_with_outfile() {
        let args = parse_args(&["vault", "-l", "mykey", "-o", "output.txt"])
            .expect("Should parse successfully");

        if let Some(Command::Lookup { key, outfile }) = args.command {
            assert_eq!(key, "mykey");
            assert_eq!(outfile, Some("output.txt".to_string()));
        } else {
            panic!("Expected Lookup command");
        }
    }

    #[test]
    fn test_delete_command() {
        let args = parse_args(&["vault", "delete", "mykey"]).expect("Should parse successfully");

        if let Some(Command::Delete { key }) = args.command {
            assert_eq!(key, "mykey");
        } else {
            panic!("Expected Delete command");
        }
    }

    #[test]
    fn test_delete_command_short_flag() {
        let args = parse_args(&["vault", "-d", "mykey"]).expect("Should parse successfully");

        assert!(matches!(args.command, Some(Command::Delete { .. })));
    }

    #[test]
    fn test_exists_command() {
        let args = parse_args(&["vault", "--exists", "mykey"]).expect("Should parse successfully");

        if let Some(Command::Exists { key }) = args.command {
            assert_eq!(key, "mykey");
        } else {
            panic!("Expected Exists command");
        }
    }

    #[test]
    fn test_init_command() {
        let args =
            parse_args(&["vault", "init", "my-vault-stack"]).expect("Should parse successfully");

        if let Some(Command::Init { name }) = args.command {
            assert_eq!(name, Some("my-vault-stack".to_string()));
        } else {
            panic!("Expected Init command");
        }
    }

    #[test]
    fn test_init_command_short_flag() {
        let args =
            parse_args(&["vault", "-i", "my-vault-stack"]).expect("Should parse successfully");

        assert!(matches!(args.command, Some(Command::Init { .. })));
    }

    #[test]
    fn test_update_command() {
        let args = parse_args(&["vault", "update"]).expect("Should parse successfully");

        if let Some(Command::Update { name }) = args.command {
            assert_eq!(name, None);
        } else {
            panic!("Expected Update command");
        }
    }

    #[test]
    fn test_update_command_with_name() {
        let args =
            parse_args(&["vault", "-u", "my-vault-stack"]).expect("Should parse successfully");

        if let Some(Command::Update { name }) = args.command {
            assert_eq!(name, Some("my-vault-stack".to_string()));
        } else {
            panic!("Expected Update command");
        }
    }

    #[test]
    fn test_encrypt_command() {
        let args =
            parse_args(&["vault", "encrypt", "secret-value"]).expect("Should parse successfully");

        if let Some(Command::Encrypt { value, .. }) = args.command {
            assert_eq!(value, Some("secret-value".to_string()));
        } else {
            panic!("Expected Encrypt command");
        }
    }

    #[test]
    fn test_encrypt_command_short_flag() {
        let args = parse_args(&["vault", "-e", "secret-value"]).expect("Should parse successfully");

        assert!(matches!(args.command, Some(Command::Encrypt { .. })));
    }

    #[test]
    fn test_decrypt_command() {
        let args = parse_args(&["vault", "decrypt", "encrypted-value"])
            .expect("Should parse successfully");

        if let Some(Command::Decrypt { value, .. }) = args.command {
            assert_eq!(value, Some("encrypted-value".to_string()));
        } else {
            panic!("Expected Decrypt command");
        }
    }

    #[test]
    fn test_decrypt_command_short_flag() {
        let args =
            parse_args(&["vault", "-y", "encrypted-value"]).expect("Should parse successfully");

        assert!(matches!(args.command, Some(Command::Decrypt { .. })));
    }

    #[test]
    fn test_describe_command() {
        let args = parse_args(&["vault", "--describe"]).expect("Should parse successfully");

        assert!(matches!(args.command, Some(Command::Describe {})));
    }

    #[test]
    fn test_info_command() {
        let args = parse_args(&["vault", "--info"]).expect("Should parse successfully");

        assert!(matches!(args.command, Some(Command::Info {})));
    }

    #[test]
    fn test_id_command() {
        let args = parse_args(&["vault", "id"]).expect("Should parse successfully");

        assert!(matches!(args.command, Some(Command::Id {})));
    }

    #[test]
    fn test_completion_command() {
        let args = parse_args(&["vault", "completion", "bash"]).expect("Should parse successfully");

        if let Some(Command::Completion { shell, install }) = args.command {
            assert_eq!(shell, Shell::Bash);
            assert!(!install);
        } else {
            panic!("Expected Completion command");
        }
    }

    #[test]
    fn test_completion_command_with_install() {
        let args = parse_args(&["vault", "--completion", "zsh", "--install"])
            .expect("Should parse successfully");

        if let Some(Command::Completion { shell, install }) = args.command {
            assert_eq!(shell, Shell::Zsh);
            assert!(install);
        } else {
            panic!("Expected Completion command");
        }
    }

    // ==================== Stack Subcommand Tests ====================

    #[test]
    fn test_stack_command_no_action() {
        let args = parse_args(&["vault", "stack"]).expect("Should parse successfully");

        if let Some(Command::Stack { action }) = args.command {
            assert!(action.is_none());
        } else {
            panic!("Expected Stack command");
        }
    }

    #[test]
    fn test_stack_list_command() {
        let args = parse_args(&["vault", "stack", "list"]).expect("Should parse successfully");

        if let Some(Command::Stack { action }) = args.command {
            assert!(matches!(action, Some(StackAction::List)));
        } else {
            panic!("Expected Stack command");
        }
    }

    #[test]
    fn test_stack_list_command_variants() {
        let variants = ["list", "-l", "--list", "l", "ls"];
        for variant in variants {
            let args = parse_args(&["vault", "stack", variant])
                .unwrap_or_else(|_| panic!("Should parse 'stack {variant}'"));
            if let Some(Command::Stack { action }) = args.command {
                assert!(
                    matches!(action, Some(StackAction::List)),
                    "Failed for variant: {variant}"
                );
            } else {
                panic!("Expected Stack command for variant: {variant}");
            }
        }
    }

    #[test]
    fn test_stack_delete_command() {
        let args = parse_args(&["vault", "stack", "delete", "my-vault"])
            .expect("Should parse successfully");

        if let Some(Command::Stack { action }) = args.command {
            if let Some(StackAction::Delete { name, force, .. }) = action {
                assert_eq!(name, Some("my-vault".to_string()));
                assert!(!force);
            } else {
                panic!("Expected StackAction::Delete");
            }
        } else {
            panic!("Expected Stack command");
        }
    }

    #[test]
    fn test_stack_delete_with_force() {
        let args = parse_args(&["vault", "stack", "--delete", "my-vault", "--force"])
            .expect("Should parse successfully");

        if let Some(Command::Stack { action }) = args.command {
            if let Some(StackAction::Delete { name, force, .. }) = action {
                assert_eq!(name, Some("my-vault".to_string()));
                assert!(force);
            } else {
                panic!("Expected StackAction::Delete");
            }
        } else {
            panic!("Expected Stack command");
        }
    }

    #[test]
    fn test_stack_with_global_args_after() {
        // Test that global args work after stack subcommand
        let args = parse_args(&["vault", "stack", "list", "-r", "eu-west-1"])
            .expect("Should parse successfully");

        assert_eq!(args.region, Some("eu-west-1".to_string()));
        if let Some(Command::Stack { action }) = args.command {
            assert!(matches!(action, Some(StackAction::List)));
        } else {
            panic!("Expected Stack command");
        }
    }

    // ==================== Edge Cases and Error Handling ====================

    #[test]
    fn test_quiet_flag_global() {
        // Quiet flag should work in various positions
        let args = parse_args(&["vault", "-q", "--all"]).expect("Should parse successfully");
        assert!(args.quiet);

        let args = parse_args(&["vault", "--all", "-q"]).expect("Should parse successfully");
        assert!(args.quiet);

        let args = parse_args(&["vault", "store", "key", "value", "-q"])
            .expect("Should parse successfully");
        assert!(args.quiet);
    }

    #[test]
    fn test_conflicting_value_args_in_store() {
        // Cannot use both positional value and --value flag
        let result = parse_args(&["vault", "store", "key", "value", "--value", "other"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_conflicting_value_and_file_in_store() {
        // Cannot use both value and file
        let result = parse_args(&["vault", "store", "key", "value", "--file", "path/to/file"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_args() {
        // Lookup requires a key
        let result = parse_args(&["vault", "lookup"]);
        assert!(result.is_err());

        // Delete requires a key
        let result = parse_args(&["vault", "delete"]);
        assert!(result.is_err());

        // Exists requires a key
        let result = parse_args(&["vault", "--exists"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_command_shows_help() {
        // Without any command, clap should error (arg_required_else_help = true)
        let result = parse_args(&["vault"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_command() {
        let result = parse_args(&["vault", "unknown-command"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_flag() {
        let result = parse_args(&["vault", "--unknown-flag", "--all"]);
        assert!(result.is_err());
    }

    // ==================== Complex Scenarios ====================

    #[test]
    fn test_lookup_with_all_global_options() {
        let args = parse_args(&[
            "vault",
            "lookup",
            "mykey",
            "-r",
            "ap-southeast-1",
            "-b",
            "prod-bucket",
            "-p",
            "prod/",
            "--vaultstack",
            "prod-vault",
            "-q",
        ])
        .expect("Should parse successfully");

        assert_eq!(args.region, Some("ap-southeast-1".to_string()));
        assert_eq!(args.bucket, Some("prod-bucket".to_string()));
        assert_eq!(args.prefix, Some("prod/".to_string()));
        assert_eq!(args.vault_stack, Some("prod-vault".to_string()));
        assert!(args.quiet);

        if let Some(Command::Lookup { key, .. }) = args.command {
            assert_eq!(key, "mykey");
        } else {
            panic!("Expected Lookup command");
        }
    }

    #[test]
    fn test_init_with_vaultstack_global_and_positional() {
        // When both --vaultstack and positional name are provided,
        // the run() function prefers vault_stack over name
        let args = parse_args(&[
            "vault",
            "--vaultstack",
            "global-name",
            "init",
            "positional-name",
        ])
        .expect("Should parse successfully");

        assert_eq!(args.vault_stack, Some("global-name".to_string()));
        if let Some(Command::Init { name }) = args.command {
            assert_eq!(name, Some("positional-name".to_string()));
        } else {
            panic!("Expected Init command");
        }
    }

    #[test]
    fn test_decrypt_with_file_flag() {
        let args = parse_args(&[
            "vault",
            "decrypt",
            "--file",
            "encrypted.bin",
            "-o",
            "output.txt",
        ])
        .expect("Should parse successfully");

        if let Some(Command::Decrypt {
            value,
            file,
            outfile,
            ..
        }) = args.command
        {
            assert_eq!(value, None);
            assert_eq!(file, Some("encrypted.bin".to_string()));
            assert_eq!(outfile, Some("output.txt".to_string()));
        } else {
            panic!("Expected Decrypt command");
        }
    }

    #[test]
    fn test_encrypt_with_file_flag() {
        let args = parse_args(&["vault", "-e", "--file", "secret.txt"])
            .expect("Should parse successfully");

        if let Some(Command::Encrypt { value, file, .. }) = args.command {
            assert_eq!(value, None);
            assert_eq!(file, Some("secret.txt".to_string()));
        } else {
            panic!("Expected Encrypt command");
        }
    }
}
