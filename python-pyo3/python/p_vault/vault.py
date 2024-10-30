import sys

from p_vault import nitor_vault_rs


def main():
    try:
        # Override the script name in the arguments list so the Rust CLI works correctly
        args = ["vault"] + sys.argv[1:]
        nitor_vault_rs.run(args)
    except KeyboardInterrupt:
        print("\naborted")
        exit(1)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
