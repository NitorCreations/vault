package main

import (
	"flag"
	"fmt"
	"log"
	"nitor_vault/vault"
	"os"
	"runtime/debug"
)

func main() {
	// TODO: replace "flag" implementation with e.g. https://github.com/spf13/cobra
	aFlag := flag.Bool("a", false, "list all flag")
	lFlag := flag.String("l", "", "lookup flag, usage: -l <key>")
	sFlag := flag.String("s", "", "store flag, usage together with -v: -s <key> -v <value string>")
	vFlag := flag.String("v", "", "value used with store flag")
	wFlag := flag.Bool("w", false, "overwrite flag used with store flag")
	versionFlag := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println(VersionInfo())
		os.Exit(0)
	}

	// Check if the flags are provided and act accordingly
	if *aFlag {
		nVault := initVault()
		all(nVault)
	} else if *lFlag != "" {
		nVault := initVault()
		lookup(nVault, lFlag)
	} else if *sFlag != "" && *vFlag != "" {
		nVault := initVault()
		if !*wFlag {
			exists, err := nVault.Exists(*sFlag)
			if err != nil {
				log.Fatal(err)
			}
			if exists {
				fmt.Printf("key %s already exists and -w flag not provided, provide it to confirm overwrite\n", *sFlag)
				return
			}
		}
		store(nVault, sFlag, []byte(*vFlag))
	} else {
		flag.CommandLine.Usage()
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
