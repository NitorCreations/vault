from typing import Any, Dict, List, Optional

class VaultConfig:
    """
    Optional parameters for a `Vault` instance.

    Attributes:
        vault_stack (Optional[str]): The name of the CloudFormation stack.
        region (Optional[str]): The AWS region for the bucket.
        bucket (Optional[str]): The name of the S3 bucket.
        key (Optional[str]): The encryption key ARN.
        prefix (Optional[str]): The prefix for keys.
        profile (Optional[str]): The AWS profile name.
        iam_id (Optional[str]): The IAM user ID.
        iam_secret (Optional[str]): The IAM secret key.
    """

    vault_stack: Optional[str]
    region: Optional[str]
    bucket: Optional[str]
    key: Optional[str]
    prefix: Optional[str]
    profile: Optional[str]
    iam_id: Optional[str]
    iam_secret: Optional[str]

    def __init__(
        self,
        vault_stack: Optional[str] = None,
        region: Optional[str] = None,
        bucket: Optional[str] = None,
        key: Optional[str] = None,
        prefix: Optional[str] = None,
        profile: Optional[str] = None,
        iam_id: Optional[str] = None,
        iam_secret: Optional[str] = None,
    ) -> None:
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

def delete_many(names: List[str], config: VaultConfig) -> None:
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

def init(config: VaultConfig) -> Dict[str, Any]:
    """
    Initialize a new Vault stack.

    Args:
        config: Vault configuration.

    Returns:
        A dictionary containing stack initialization details.
    """

def list_all(config: VaultConfig) -> List[str]:
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

def run(args: List[str]) -> None:
    """
    Run Vault CLI with the given arguments.

    Args:
        args: List of command-line arguments.
    """

def stack_status(config: VaultConfig) -> Dict[str, Any]:
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

def update(config: VaultConfig) -> Dict[str, Any]:
    """
    Update the Vault CloudFormation stack with the current template.

    Args:
        config: Vault configuration.

    Returns:
        A dictionary with the stack update details.
    """
