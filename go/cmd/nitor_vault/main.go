package main

import (
	"flag"
	"fmt"
	"log"
	"nitor_vault/vault"
)

func main() {
	// TODO: replace "flag" implementation with e.g. https://github.com/spf13/cobra
	aFlag := flag.Bool("a", false, "list all flag")
	lFlag := flag.String("l", "", "lookup flag, usage: -l <key>")
	sFlag := flag.String("s", "", "store flag, usage together with -v: -s <key> -v <value string>")
	vFlag := flag.String("v", "", "value used with store flag")
	wFlag := flag.Bool("w", false, "overwrite flag used with store flag")
	flag.Parse()

	// Check if the flags are provided and act accordingly
	if *aFlag {
		vault := initVault()
		all(vault)
	} else if *lFlag != "" {
		vault := initVault()
		lookup(vault, lFlag)
	} else if *sFlag != "" && *vFlag != "" {
		vault := initVault()
		if !*wFlag {
			exists, err := vault.Exists(*sFlag)
			if err != nil {
				log.Fatal(err)
			}
			if exists {
				fmt.Printf("key %s already exists and -w flag not provided, provide it to confirm overwrite\n", *sFlag)
				return
			}
		}
		store(vault, sFlag, []byte(*vFlag))
	} else {
		flag.CommandLine.Usage()
	}
}

// CLI helper functions
func initVault() vault.Vault {
	vault, err := vault.LoadVault()
	if err != nil {
		log.Fatal(err)
	}
	return vault
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
