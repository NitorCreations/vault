from n_vault import nitor_vault_rs


class Vault:
    """Nitor Vault wrapper around the Rust vault library."""

    @staticmethod
    def lookup(name: str) -> str:
        return nitor_vault_rs.lookup(name)

    @staticmethod
    def list_all() -> list[str]:
        return nitor_vault_rs.list_all()
