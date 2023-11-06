package main

import (
	"fmt"
	"log"
	"nitor_vault/vault"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	aFlag       bool
	lFlag       string
	sFlag       string
	vFlag       string
	wFlag       bool
	versionFlag bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "nitor-vault",
		Short: "Encrypted AWS key-value storage",
		Long:  "Nitor Vault, see https://github.com/nitorcreations/vault for usage examples",
		Run: func(cmd *cobra.Command, args []string) {
			if versionFlag {
				fmt.Println(VersionInfo())
				return
			}

			if len(args) <= 0 || !cmd.Flags().HasFlags() {
				cmd.Help()
				os.Exit(0)
			}

			nVault := initVault()

			switch {
			case aFlag:
				all(nVault)
			case lFlag != "":
				lookup(nVault, &lFlag)
			case sFlag != "" && vFlag != "":
				if !wFlag {
					exists, err := nVault.Exists(sFlag)
					if err != nil {
						log.Fatal(err)
					}
					if exists {
						fmt.Printf("Key %s already exists and -w flag not provided, provide it to confirm overwrite\n", sFlag)
						return
					}
				}
				store(nVault, &sFlag, []byte(vFlag))
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
			fmt.Println(VersionInfo())
		},
	}

	// All command
	var allCmd = &cobra.Command{
		Use:   "all",
		Short: "List all available secrets",
		Run: func(cmd *cobra.Command, args []string) {
			nVault := initVault()
			all(nVault)
		},
	}

	// Lookup command
	var lookupCmd = &cobra.Command{
		Use:   "lookup [key]",
		Short: "Lookup secret value for key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			nVault := initVault()
			lookup(nVault, &args[0])
		},
	}

	// Store command
	var storeCmd = &cobra.Command{
		Use:   "store [key] [value]",
		Short: "Store an entry",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			nVault := initVault()
			store(nVault, &args[0], []byte(args[1]))
		},
	}

	// Add overwrite flag to store command
	storeCmd.Flags().BoolVarP(&wFlag, "overwrite", "w", false, "Overwrite the existing entry")

	rootCmd.Flags().BoolVarP(&versionFlag, "version", "", false, "Print version information and exit")
	rootCmd.Flags().BoolVarP(&aFlag, "all", "a", false, "List all available secrets")
	rootCmd.Flags().StringVarP(&lFlag, "lookup", "l", "", "Lookup secret value for key, usage: -l <key>")
	rootCmd.Flags().StringVarP(&sFlag, "store", "s", "", "Store flag, usage together with -v: -s <key> -v <value string>")
	rootCmd.Flags().StringVarP(&vFlag, "value", "v", "", "Value used with store flag")
	rootCmd.Flags().BoolVarP(&wFlag, "overwrite", "w", false, "Overwrite flag used with store flag")

	// Add all subcommands to the root command
	rootCmd.AddCommand(versionCmd, allCmd, lookupCmd, storeCmd)

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

// CLI helper functions
func initVault() vault.Vault {
	nVault, err := vault.LoadVault()
	if err != nil {
		log.Fatal(err)
	}
	return nVault
}

func all(vault vault.Vault) {
	all, err := vault.All()
	if err != nil {
		log.Fatal(err)
	}
	for _, key := range all {
		fmt.Println(key)
	}
}

func lookup(vault vault.Vault, key *string) {
	res, err := vault.Lookup(*key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", res)
}

func store(vault vault.Vault, key *string, value []byte) {
	err := vault.Store(*key, value)
	if err != nil {
		log.Fatal(err)
	}
}

// VersionInfo Returns formatted build version info string.
func VersionInfo() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		goVersion := info.GoVersion
		commit := "unknown"
		timestamp := "unknown"
		arch := "unknown"
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				commit = setting.Value
			}
			if setting.Key == "vcs.time" {
				timestamp = setting.Value
			}
			if setting.Key == "GOARCH" {
				arch = setting.Value
			}
		}
		return fmt.Sprintf("%s %s %s %s %s %s", vault.VersionNumber, timestamp, vault.GitBranch, commit, goVersion, arch)
	}
	return ""
}
