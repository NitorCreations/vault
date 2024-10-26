import re

from dataclasses import dataclass
from pathlib import Path

import typer

from typer.core import TyperGroup

from n_vault import nitor_vault


# Hack to nicely support command aliases
# https://github.com/fastapi/typer/issues/132
class AliasGroup(TyperGroup):
    _CMD_SPLIT_P = re.compile(r" ?[,|] ?")

    def get_command(self, ctx, cmd_name):
        cmd_name = self._group_cmd_name(cmd_name)
        return super().get_command(ctx, cmd_name)

    def _group_cmd_name(self, default_name):
        for cmd in self.commands.values():
            name = cmd.name
            if name and default_name in self._CMD_SPLIT_P.split(name):
                return name

        return default_name


@dataclass
class Config:
    """Global options."""

    vault_stack: str | None
    region: str | None
    bucket: str | None
    key_arn: str | None
    prefix: str | None
    quiet: bool


app = typer.Typer(
    cls=AliasGroup,
    short_help="Encrypted AWS key-value storage utility",
    help="Nitor Vault CLI, see https://github.com/nitorcreations/vault for usage examples",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    bucket: str | None = typer.Option(
        None,
        "--bucket",
        "-b",
        envvar="VAULT_BUCKET",
        help="Override the bucket name",
    ),
    key_arn: str | None = typer.Option(
        None,
        "--key-arn",
        "-k",
        envvar="VAULT_KEY",
        help="Override the KMS key ARN",
    ),
    prefix: str | None = typer.Option(
        None,
        "--prefix",
        "-p",
        envvar="VAULT_PREFIX",
        help="Optional prefix for key name",
    ),
    region: str | None = typer.Option(
        None,
        "--region",
        "-r",
        envvar="AWS_REGION",
        help="Specify AWS region for the bucket",
    ),
    vault_stack: str | None = typer.Option(
        None,
        "--vault-stack",
        envvar="VAULT_STACK",
        help="Specify CloudFormation stack name to use",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress additional output and error messages",
    ),
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        is_eager=True,
        help="Print version and exit",
    ),
):
    """
    Global options available in all subcommands.
    """
    if version:
        # Get the version number from the Rust project definition,
        # which is also what pip / pypi uses.
        print(f"Nitor Vault {nitor_vault.version()}")
        raise typer.Exit()

    # Store global config in Typer context
    config = Config(
        vault_stack=vault_stack,
        region=region,
        bucket=bucket,
        key_arn=key_arn,
        prefix=prefix,
        quiet=quiet,
    )
    ctx.obj = config


@app.command(name="all | a | list | ls")
def all_keys(ctx: typer.Context):
    """List available secrets"""
    config: Config = ctx.obj
    nitor_vault.all(config.vault_stack, config.region, config.bucket, config.key_arn, config.prefix)


@app.command(name="delete | d")
def delete(ctx: typer.Context, key: str = typer.Argument(..., help="Key name to delete", show_default=False)):
    """Delete an existing key from the store"""
    config: Config = ctx.obj
    nitor_vault.delete(
        key,
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
    )


@app.command()
def describe(ctx: typer.Context):
    """Print CloudFormation stack parameters for current configuration"""
    config: Config = ctx.obj
    nitor_vault.describe(
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
    )


@app.command(name="decrypt | y")
def decrypt(
    ctx: typer.Context,
    value: str | None = typer.Argument(
        None,
        help="Value to decrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    value_argument: str | None = typer.Option(
        None,
        "-v",
        "--value",
        help="Value to decrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    file: Path | None = typer.Option(
        None,
        "-f",
        "--file",
        help="File to decrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    outfile: Path | None = typer.Option(
        None,
        "-o",
        "--outfile",
        help="Optional output file",
        show_default=False,
    ),
):
    """Directly decrypt given value"""
    config: Config = ctx.obj
    nitor_vault.decrypt(
        value,
        value_argument,
        str(file) if file else None,
        str(outfile) if outfile else None,
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
    )


@app.command(name="encrypt | e")
def encrypt(
    ctx: typer.Context,
    value: str | None = typer.Argument(
        None,
        help="Value to encrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    value_argument: str | None = typer.Option(
        None,
        "-v",
        "--value",
        help="Value to encrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    file: Path | None = typer.Option(
        None,
        "-f",
        "--file",
        help="File to encrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    outfile: Path | None = typer.Option(
        None,
        "-o",
        "--outfile",
        help="Optional output file",
        show_default=False,
    ),
):
    """Directly encrypt given value"""
    config: Config = ctx.obj
    nitor_vault.encrypt(
        value,
        value_argument,
        str(file) if file else None,
        str(outfile) if outfile else None,
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
    )


@app.command()
def exists(ctx: typer.Context, key: str = typer.Argument(..., help="Key name to check", show_default=False)):
    """
    Check if a key exists

    Exits with code 0 if the key exists, code 5 if it does *not* exist, and with code 1 for other errors.
    """
    config: Config = ctx.obj
    result = nitor_vault.exists(
        key,
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
        config.quiet,
    )
    if not result:
        raise typer.Exit(code=5)


@app.command()
def info(ctx: typer.Context):
    """Print vault information"""
    config: Config = ctx.obj
    nitor_vault.info(
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
    )


@app.command("id")
def caller_id(ctx: typer.Context):
    """Print AWS user account information"""
    config: Config = ctx.obj
    nitor_vault.id(config.region, config.quiet)


@app.command(name="init | i")
def init(ctx: typer.Context, name: str | None = typer.Argument(None, help="Vault stack name", show_default=False)):
    """
    Initialize a new KMS key and S3 bucket

    Initialize a KMS key and an S3 bucket with roles for reading and writing on a fresh account via CloudFormation.
    The account used must have rights to create the resources.

    Usage examples:
    - `vault init`
    - `vault init "vault-name"`
    - `vault --vault-stack "vault-name" init`
    - `VAULT_STACK="vault-name" vault i`
    """
    config: Config = ctx.obj
    nitor_vault.init(name, config.vault_stack, config.region, config.bucket, config.quiet)


@app.command(name="lookup | l")
def lookup(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="Key name to lookup", show_default=False),
    outfile: Path | None = typer.Option(None, "-o", "--outfile", help="Optional output file", show_default=False),
):
    """Output secret value for given key"""
    config: Config = ctx.obj
    nitor_vault.lookup(
        key,
        # Convert Path to string since this seems to be the simplest way to pass it
        str(outfile) if outfile else None,
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
    )


@app.command()
def status(ctx: typer.Context):
    """Print vault stack information"""
    config: Config = ctx.obj
    nitor_vault.status(config.vault_stack, config.region, config.bucket, config.key_arn, config.prefix, config.quiet)


@app.command(name="store | s")
def store(
    ctx: typer.Context,
    key: str | None = typer.Argument(None, help="Key name to use for stored value", show_default=False),
    value: str | None = typer.Argument(None, help="Value to store, use '-' for stdin", show_default=False),
    value_argument: str | None = typer.Option(
        None,
        "-v",
        "--value",
        help="Value to store, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    file: Path | None = typer.Option(
        None,
        "-f",
        "--file",
        help="File to store, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    overwrite: bool = typer.Option(
        False,
        "-w",
        "--overwrite",
        help="Overwrite existing key",
        show_default=False,
    ),
):
    """
    Store a new key-value pair

    Store a new key-value pair in the vault.
    You can provide the key and value directly, or specify a file to store.

    Usage examples:
    - Store a value: `vault store "my-key" "some value"`
    - Store a value from args: `vault store mykey --value "some value"`
    - Store from a file: `vault store mykey --file path/to/file.txt`
    - Store from a file with filename as key: `vault store --file path/to/file.txt`
    - Store from stdin: `echo "some data" | vault store mykey -`
    - Store from stdin: `cat file.zip | vault store mykey --file -`
    """
    if (value and value_argument) or (value_argument and file) or (value and file):
        raise typer.BadParameter("Specify only one of positional value, '--value' or '--file'")

    config: Config = ctx.obj
    nitor_vault.store(
        key,
        value,
        value_argument,
        str(file) if file else None,
        overwrite,
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
        config.quiet,
    )


@app.command(name="update | u")
def update(ctx: typer.Context, name: str = typer.Option(None, help="Optional vault stack name", show_default=False)):
    """
    Update the vault CloudFormation stack

    Update the CloudFormation stack which declares all resources needed by the vault.

    Usage examples:
    - `vault update`
    - `vault update "vault-name"`
    - `vault u "vault-name"`
    - `vault --vault-stack "vault-name" update`
    - `VAULT_STACK="vault-name" vault u`
    """
    config: Config = ctx.obj
    nitor_vault.update(
        name, config.vault_stack, config.region, config.bucket, config.key_arn, config.prefix, config.quiet
    )


if __name__ == "__main__":
    app()
