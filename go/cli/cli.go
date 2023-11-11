package cli

import (
	"fmt"
	"log"
	vault "nitor_vault/nvault"
	"runtime/debug"
)

// CLI helper functions

func InitVault(vaultstackFlag string) vault.Vault {
	nVault, err := vault.LoadVault(vaultstackFlag)
	if err != nil {
		log.Fatal(err)
	}
	return nVault
}

func All(vault vault.Vault) {
	all, err := vault.All()
	if err != nil {
		log.Fatal(err)
	}
	for _, key := range all {
		fmt.Println(key)
	}
}

func Lookup(vault vault.Vault, key *string) {
	res, err := vault.Lookup(*key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", res)
}

func Delete(vault vault.Vault, key *string) {
	err := vault.Delete(*key)
	if err != nil {
		log.Fatal(err)
	}
}

func Store(vault vault.Vault, key *string, value []byte) {
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
		return fmt.Sprintf("%s %s %s %s %s %s", VersionNumber, timestamp, GitBranch, commit, goVersion, arch)
	}
	return ""
}
