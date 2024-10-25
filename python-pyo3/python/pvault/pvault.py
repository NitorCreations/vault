import nvault
import typer

from nvault import sum_as_string

app = typer.Typer(help="Nitor Vault CLI, see https://github.com/nitorcreations/vault for usage examples")


@app.command()
def all():
    """List available secrets"""
    typer.echo("Listing all secrets...")


@app.command()
def delete(key: str):
    """Delete an existing key from the store"""
    typer.echo(f"Deleting key: {key}")


@app.command()
def describe():
    """Describe CloudFormation stack parameters for current configuration"""
    typer.echo("Describing CloudFormation stack...")
    result = sum_as_string(1,3)
    print(f"sum_as_string(1,3) = {result}")


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
    typer.echo("AWS account ID information")


@app.command()
def status():
    """Print vault stack information"""
    typer.echo("Vault stack status")
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
def lookup(key: str, outfile: str | None = None):
    """Output secret value for given key"""
    typer.echo(f"Looking up key: {key}")
    if outfile:
        typer.echo(f"Saving output to: {outfile}")


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


if __name__ == "__main__":
    app()
