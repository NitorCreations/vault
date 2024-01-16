package main

import (
	"fmt"
	"log"
	"os"

	"github.com/nitorcreations/vault/go/cli"
	"github.com/spf13/cobra"
)

var (
	allFlag        bool
	lookupFlag     string
	deleteFlag     string
	storeFlag      string
	valueFlag      string
	writeFlag      bool
	versionFlag    bool
	vaultStackFlag string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "vault",
		Short: "Encrypted AWS key-value storage",
		Long:  "Nitor Vault, see https://github.com/nitorcreations/vault for usage examples",
		Run: func(cmd *cobra.Command, args []string) {
			if versionFlag {
				fmt.Println(cli.VersionInfo())
				return
			}

			if !cmd.Flags().HasFlags() {
				cmd.Help()
				os.Exit(0)
			}

			nVault := cli.InitVault(vaultStackFlag)

			switch {
			case allFlag:
				cli.All(nVault)
			case lookupFlag != "":
				cli.Lookup(nVault, &lookupFlag)
			case storeFlag != "" && valueFlag != "":
				if !writeFlag {
					exists, err := nVault.Exists(storeFlag)
					if err != nil {
						log.Fatal(err)
					}
					if exists {
						fmt.Printf("Key '%s' already exists and -w flag not provided, provide it to confirm overwrite\n", storeFlag)
						return
					}
				}
				cli.Store(nVault, &storeFlag, []byte(valueFlag))
			case deleteFlag != "":
				cli.Delete(nVault, &deleteFlag)
			default:
				cmd.Help()
			}
		},
	}

	// Version command
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version information and exit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(cli.VersionInfo())
		},
	}

	// All command
	var allCmd = &cobra.Command{
		Use:   "all",
		Short: "List all available secrets",
		Run: func(cmd *cobra.Command, args []string) {
			nVault := cli.InitVault(vaultStackFlag)
			cli.All(nVault)
		},
	}

	// Lookup command
	var lookupCmd = &cobra.Command{
		Use:   "lookup [key]",
		Short: "Lookup secret value for key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			nVault := cli.InitVault(vaultStackFlag)
			cli.Lookup(nVault, &args[0])
		},
	}

	// Store command
	var storeCmd = &cobra.Command{
		Use:   "store [key] [value]",
		Short: "Store an entry",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			nVault := cli.InitVault(vaultStackFlag)
			cli.Store(nVault, &args[0], []byte(args[1]))
		},
	}

	// Delete command
	var deleteCmd = &cobra.Command{
		Use:   "delete [key]",
		Short: "Delete secret value for key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			nVault := cli.InitVault(vaultStackFlag)
			cli.Delete(nVault, &args[0])
		},
	}
	// Add overwrite flag to store command
	storeCmd.Flags().BoolVarP(&writeFlag, "overwrite", "w", false, "Overwrite the existing entry")

	rootCmd.Flags().BoolVarP(&versionFlag, "version", "", false, "Print version information and exit")
	rootCmd.Flags().BoolVarP(&allFlag, "all", "a", false, "List all available secrets")
	rootCmd.Flags().StringVarP(&lookupFlag, "lookup", "l", "", "Lookup secret value for key, usage: -l <key>")
	rootCmd.Flags().StringVarP(&deleteFlag, "delete", "d", "", "Delete secret value for key, usage: -d <key>")
	rootCmd.Flags().StringVarP(&storeFlag, "store", "s", "", "Store flag, usage together with -v: -s <key> -v <value string>")
	rootCmd.Flags().StringVarP(&valueFlag, "value", "v", "", "Value used with store flag")
	// the default is written in library side, don't put it here as it will break ENV variable
	rootCmd.Flags().StringVar(&vaultStackFlag, "vaultstack", "", "Optional CloudFormation stack to lookup key and bucket. 'vault' by default (also by env: VAULT_STACK=)")
	rootCmd.Flags().BoolVarP(&writeFlag, "overwrite", "w", false, "Overwrite flag used with store flag")

	// Add all subcommands to the root command
	rootCmd.AddCommand(versionCmd, allCmd, lookupCmd, storeCmd, deleteCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
