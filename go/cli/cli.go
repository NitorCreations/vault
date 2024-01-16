package cli

import (
	"fmt"
	"log"

	"runtime/debug"

	vault "github.com/nitorcreations/vault/go/nvault"
)

// CLI helper functions

// Info variables are set at build time

var GitBranch string
var GitHash string
var Timestamp string

func InitVault(vaultStackFlag string) vault.Vault {
	nVault, err := vault.LoadVault(vaultStackFlag)
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
		arch := "unknown"
		for _, setting := range info.Settings {
			if setting.Key == "GOARCH" {
				arch = setting.Value
			}
		}
		return fmt.Sprintf("%s %s %s %s %s %s", VersionNumber, Timestamp, GitBranch, GitHash, goVersion, arch)
	}
	return fmt.Sprintf("%s %s %s %s", VersionNumber, Timestamp, GitBranch, GitHash)
}
