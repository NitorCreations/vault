from dataclasses import dataclass
from pathlib import Path

import nvault
import typer

app = typer.Typer(
    short_help="Encrypted AWS key-value storage utility",
    help="Nitor Vault CLI, see https://github.com/nitorcreations/vault for usage examples",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)


# Define a Config dataclass for the global options
@dataclass
class Config:
    bucket: str | None
    key_arn: str | None
    prefix: str | None
    region: str | None
    vault_stack: str | None
    quiet: bool


# Define global options in the main function
def main(
    bucket: str | None = typer.Option(None, "--bucket", "-b", envvar="VAULT_BUCKET", help="Override the bucket name"),
    key_arn: str | None = typer.Option(None, "--key-arn", "-k", envvar="VAULT_KEY", help="Override the KMS key ARN"),
    prefix: str | None = typer.Option(
        None, "--prefix", "-p", envvar="VAULT_PREFIX", help="Optional prefix for key name"
    ),
    region: str | None = typer.Option(
        None, "--region", "-r", envvar="AWS_REGION", help="Specify AWS region for the bucket"
    ),
    vault_stack: str | None = typer.Option(
        None, "--vault-stack", envvar="VAULT_STACK", help="Specify CloudFormation stack name to use"
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress additional output and error messages"),
):
    """
    CLI with global options available in all subcommands.
    """
    # Initialize Config dataclass and store it in Typer context
    config = Config(
        bucket=bucket,
        key_arn=key_arn,
        prefix=prefix,
        region=region,
        vault_stack=vault_stack,
        quiet=quiet,
    )
    typer.Context.obj = config


@app.command()
def all():
    """List available secrets"""
    nvault.all()


@app.command()
def delete(key: str):
    """Delete an existing key from the store"""
    typer.echo(f"Deleting key: {key}")


@app.command()
def describe():
    """Describe CloudFormation stack parameters for current configuration"""
    typer.echo("Describing CloudFormation stack...")


@app.command()
def decrypt(
    value: str | None = None,
    value_argument: str | None = typer.Option(None),
    file: str | None = typer.Option(None),
    outfile: str | None = None,
):
    """Directly decrypt given value"""
    if value:
        typer.echo(f"Decrypting value: {value}")
    elif value_argument:
        typer.echo(f"Decrypting value argument: {value_argument}")
    elif file:
        typer.echo(f"Decrypting from file: {file}")
    else:
        typer.echo("No value provided for decryption")

    if outfile:
        typer.echo(f"Saving decrypted output to: {outfile}")


@app.command()
def encrypt(
    value: str | None = None,
    value_argument: str | None = typer.Option(None),
    file: str | None = typer.Option(None),
    outfile: str | None = None,
):
    """Directly encrypt given value"""
    if value:
        typer.echo(f"Encrypting value: {value}")
    elif value_argument:
        typer.echo(f"Encrypting value argument: {value_argument}")
    elif file:
        typer.echo(f"Encrypting from file: {file}")
    else:
        typer.echo("No value provided for encryption")

    if outfile:
        typer.echo(f"Saving encrypted output to: {outfile}")


@app.command()
def exists(key: str):
    """Check if a key exists"""
    typer.echo(f"Checking if key exists: {key}")


@app.command()
def info():
    """Print vault information"""
    typer.echo("Vault information")


@app.command()
def id():
    """Print AWS user account information"""
    nvault.id()


@app.command()
def status():
    """Print vault stack information"""
    nvault.status()


@app.command()
def init(name: str | None = None):
    """Initialize a new KMS key and S3 bucket"""
    if name:
        typer.echo(f"Initializing vault with stack name: {name}")
    else:
        typer.echo("Initializing vault with default stack name")


@app.command()
def update(name: str | None = None):
    """Update the vault CloudFormation stack"""
    if name:
        typer.echo(f"Updating vault stack with name: {name}")
    else:
        typer.echo("Updating vault with default stack name")


@app.command()
def lookup(key: str, outfile: Path = typer.Option(None, "-o", "--outfile", help="Optional output file")):
    """Output secret value for given key"""
    nvault.lookup(key, str(outfile) if outfile else None)


@app.command()
def store(
    key: str | None = None,
    value: str | None = None,
    value_argument: str | None = typer.Option(None),
    file: str | None = typer.Option(None),
    overwrite: bool = False,
):
    """Store a new key-value pair"""
    if value:
        typer.echo(f"Storing value for key: {key} with value: {value}")
    elif value_argument:
        typer.echo(f"Storing value argument for key: {key} with value: {value_argument}")
    elif file:
        typer.echo(f"Storing value from file for key: {key}")
    else:
        typer.echo("No value provided for storing")

    if overwrite:
        typer.echo("Overwrite enabled")


# Register main function as callback to apply global options
app.callback()(main)

if __name__ == "__main__":
    app()
