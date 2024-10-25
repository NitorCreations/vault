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
        None,
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
        # This gets version number from Rust project definition,
        # which is also what pip uses.
        print(f"Nitor Vault {nitor_vault.version_number()}")
        raise typer.Exit()

    # Initialize Config dataclass and store it in Typer context
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
def delete(ctx: typer.Context, key: str):
    """Delete an existing key from the store"""
    config: Config = ctx.obj
    nitor_vault.delete(
        key,
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
        config.quiet,
    )


@app.command()
def describe(ctx: typer.Context):
    """Describe CloudFormation stack parameters for current configuration"""
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
    value: str = typer.Argument(
        None,
        help="Value to decrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    value_argument: str = typer.Option(
        None,
        "-v",
        "--value",
        help="Value to decrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    file: Path = typer.Option(
        None,
        "-f",
        "--file",
        help="File to decrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    outfile: Path = typer.Option(
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
    value: str = typer.Argument(
        None,
        help="Value to encrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    value_argument: str = typer.Option(
        None,
        "-v",
        "--value",
        help="Value to encrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    file: Path = typer.Option(
        None,
        "-f",
        "--file",
        help="File to encrypt, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    outfile: Path = typer.Option(
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
def exists(ctx: typer.Context, key: str):
    """Check if a key exists"""
    config: Config = ctx.obj
    result = nitor_vault.encrypt(
        key,
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
    )
    if not result:
        raise typer.Exit(code=5)


@app.command()
def info(ctx: typer.Context):
    """Print vault information"""
    config: Config = ctx.obj
    typer.echo("Vault information")
    typer.echo(f"{config}")


@app.command("id")
def caller_id(ctx: typer.Context):
    """Print AWS user account information"""
    config: Config = ctx.obj
    nitor_vault.id(config.region, config.quiet)


@app.command(name="init | i")
def init(ctx: typer.Context, name: str | None = None):
    """Initialize a new KMS key and S3 bucket"""
    config: Config = ctx.obj
    nitor_vault.init(name, config.vault_stack, config.region, config.bucket, config.quiet)


@app.command(name="lookup | l")
def lookup(
    ctx: typer.Context,
    key: str = typer.Argument(..., help="Key name to lookup", show_default=False),
    outfile: Path = typer.Option(None, "-o", "--outfile", help="Optional output file", show_default=False),
):
    """Output secret value for given key"""
    config: Config = ctx.obj
    nitor_vault.lookup(
        key,
        config.vault_stack,
        config.region,
        config.bucket,
        config.key_arn,
        config.prefix,
        config.quiet,
        # Convert Path to string since this seems to be the simplest way to pass it
        str(outfile) if outfile else None,
    )


@app.command()
def status(ctx: typer.Context):
    """Print vault stack information"""
    config: Config = ctx.obj
    nitor_vault.status(config.vault_stack, config.region, config.bucket, config.key_arn, config.prefix, config.quiet)


@app.command(name="store | s")
def store(
    ctx: typer.Context,
    key: str = typer.Argument(None, help="Key name to use for stored value", show_default=False),
    value: str = typer.Argument(None, help="Value to store, use '-' for stdin", show_default=False),
    value_argument: str = typer.Option(
        None,
        "-v",
        "--value",
        help="Value to store, use '-' for stdin",
        allow_dash=True,
        show_default=False,
    ),
    file: Path = typer.Option(
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
    """Store a new key-value pair"""
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
    """Update the vault CloudFormation stack"""
    config: Config = ctx.obj
    nitor_vault.update(
        name, config.vault_stack, config.region, config.bucket, config.key_arn, config.prefix, config.quiet
    )


if __name__ == "__main__":
    app()
