from typing import Any

class VaultConfig:
    """
    Optional parameters for a `Vault` instance.

    Attributes:
        vault_stack (str | None): The name of the CloudFormation stack.
        region (str | None): The AWS region for the bucket.
        bucket (str | None): The name of the S3 bucket.
        key (str | None): The encryption key ARN.
        prefix (str | None): The prefix for keys.
        profile (str | None): The AWS profile name.
        iam_id (str | None): The IAM user ID.
        iam_secret (str | None): The IAM secret key.
    """

    vault_stack: str | None
    region: str | None
    bucket: str | None
    key: str | None
    prefix: str | None
    profile: str | None
    iam_id: str | None
    iam_secret: str | None

    def __init__(
        self,
        vault_stack: str | None = None,
        region: str | None = None,
        bucket: str | None = None,
        key: str | None = None,
        prefix: str | None = None,
        profile: str | None = None,
        iam_id: str | None = None,
        iam_secret: str | None = None,
    ) -> VaultConfig:
        """
        Initialize a VaultConfig instance with optional parameters.

        Args:
            vault_stack: The name of the CloudFormation stack.
            region: The AWS region for the bucket.
            bucket: The name of the S3 bucket.
            key: The encryption key ARN.
            prefix: The prefix for keys.
            profile: The AWS profile name.
            iam_id: The IAM user ID.
            iam_secret: The IAM secret key.
        """
        ...

def delete(name: str, config: VaultConfig) -> None:
    """
    Delete data in S3 for the given key name.
    """

def delete_many(names: list[str], config: VaultConfig) -> None:
    """
    Delete data for multiple keys.
    """

def direct_decrypt(data: bytes, config: VaultConfig) -> bytes:
    """
    Decrypt data with KMS.

    Args:
        data: Encrypted bytes to decrypt.
        config: Vault configuration.

    Returns:
        Decrypted bytes.
    """

def direct_encrypt(data: bytes, config: VaultConfig) -> bytes:
    """
    Encrypt data with KMS.

    Args:
        data: Plaintext bytes to encrypt.
        config: Vault configuration.

    Returns:
        Encrypted bytes.
    """

def exists(name: str, config: VaultConfig) -> bool:
    """
    Check if the given key name exists in the S3 bucket.

    Args:
        name: The key name to check.
        config: Vault configuration.

    Returns:
        True if the key exists, False otherwise.
    """

def init(config: VaultConfig) -> dict[str, Any]:
    """
    Initialize a new Vault stack.

    Args:
        config: Vault configuration.

    Returns:
        A dictionary containing stack initialization details.
    """

def list_all(config: VaultConfig) -> list[str]:
    """
    Get all available secrets.

    Args:
        config: Vault configuration.

    Returns:
        A list of key names.
    """

def lookup(name: str, config: VaultConfig) -> bytes:
    """
    Lookup the value for the given key name.

    Args:
        name: The key name to look up.
        config: Vault configuration.

    Returns:
        The raw bytes stored under the given key.
    """

def run(args: list[str]) -> None:
    """
    Run Vault CLI with the given arguments.

    Args:
        args: List of command-line arguments, including program name.
    """

def stack_status(config: VaultConfig) -> dict[str, Any]:
    """
    Get the Vault CloudFormation stack status.

    Args:
        config: Vault configuration.

    Returns:
        A dictionary with the stack status details.
    """

def store(name: str, value: bytes, config: VaultConfig) -> None:
    """
    Store an encrypted value with the given key name in S3.

    Args:
        name: Key name for the data.
        value: Bytes to store.
        config: Vault configuration.
    """

def update(config: VaultConfig) -> dict[str, Any]:
    """
    Update the Vault CloudFormation stack with the current template.

    Args:
        config: Vault configuration.

    Returns:
        A dictionary with the stack update details.
    """
