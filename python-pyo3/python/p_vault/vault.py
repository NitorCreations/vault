import sys

from p_vault import nitor_vault_rs


def main():
    # Override the script name in the arguments list so the Rust CLI works correctly
    args = ["pvault"] + sys.argv[1:]
    nitor_vault_rs.run(args)


if __name__ == "__main__":
    main()
