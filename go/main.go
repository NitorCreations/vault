package main

import (
	"fmt"
	"log"
	"nitor_vault/cli"
	"os"

	"github.com/spf13/cobra"
)

var (
	aFlag          bool
	lFlag          string
	sFlag          string
	vFlag          string
	wFlag          bool
	versionFlag    bool
	vaultstackFlag string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "nitor-vault",
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

			nVault := cli.InitVault(vaultstackFlag)

			switch {
			case aFlag:
				cli.All(nVault)
			case lFlag != "":
				cli.Lookup(nVault, &lFlag)
			case sFlag != "" && vFlag != "":
				if !wFlag {
					exists, err := nVault.Exists(sFlag)
					if err != nil {
						log.Fatal(err)
					}
					if exists {
						fmt.Printf("Key '%s' already exists and -w flag not provided, provide it to confirm overwrite\n", sFlag)
						return
					}
				}
				cli.Store(nVault, &sFlag, []byte(vFlag))
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
			nVault := cli.InitVault(vaultstackFlag)
			cli.All(nVault)
		},
	}

	// Lookup command
	var lookupCmd = &cobra.Command{
		Use:   "lookup [key]",
		Short: "Lookup secret value for key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			nVault := cli.InitVault(vaultstackFlag)
			cli.Lookup(nVault, &args[0])
		},
	}

	// Store command
	var storeCmd = &cobra.Command{
		Use:   "store [key] [value]",
		Short: "Store an entry",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			nVault := cli.InitVault(vaultstackFlag)
			cli.Store(nVault, &args[0], []byte(args[1]))
		},
	}

	// Add overwrite flag to store command
	storeCmd.Flags().BoolVarP(&wFlag, "overwrite", "w", false, "Overwrite the existing entry")

	rootCmd.Flags().BoolVarP(&versionFlag, "version", "", false, "Print version information and exit")
	rootCmd.Flags().BoolVarP(&aFlag, "all", "a", false, "List all available secrets")
	rootCmd.Flags().StringVarP(&lFlag, "lookup", "l", "", "Lookup secret value for key, usage: -l <key>")
	rootCmd.Flags().StringVarP(&sFlag, "store", "s", "", "Store flag, usage together with -v: -s <key> -v <value string>")
	rootCmd.Flags().StringVarP(&vFlag, "value", "v", "", "Value used with store flag")
	// the default is written in library side, don't put it here as it will break ENV variable
	rootCmd.Flags().StringVar(&vaultstackFlag, "vaultstack", "", "Optional CloudFormation stack to lookup key and bucket. 'vault' by default (also by env: VAULT_STACK=)")
	rootCmd.Flags().BoolVarP(&wFlag, "overwrite", "w", false, "Overwrite flag used with store flag")

	// Add all subcommands to the root command
	rootCmd.AddCommand(versionCmd, allCmd, lookupCmd, storeCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
