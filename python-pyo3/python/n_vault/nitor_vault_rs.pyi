from typing import Optional

class VaultConfig:
    """
    Optional parameters for a `Vault` instance.
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





