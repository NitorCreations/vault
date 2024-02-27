# Nitor Vault (Go Version)

A command line tool for encrypting and decrypting keys and values using client-side encryption with AWS KMS keys,
implemented in Go.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- You have installed the latest version of [Go](https://go.dev/).
- You have an AWS account with permissions to access AWS KMS, S3, and CloudFormation services.
- You have configured AWS credentials that the tool can use to access AWS services.

## Building the Tool

To build the `nitor-vault` tool, follow these steps:

```shell
./build.sh
```

Or manually:

```shell
go build -v -o nitor-vault
```

## Format code

Using [gofmt](https://pkg.go.dev/cmd/gofmt)

```shell
gofmt -s -w .
```

## Update version number

Increment minor version:

```shell
./update_version.sh
```

Override version manually:

```shell
./update_version.sh --version 1.2.3
# this also works
VERSION=1.2.3 ./update_version.sh
```

## Updating dependencies

```shell
# check for available updates
go list -u -m all
# update a specific package
go get -u example.com/pkg
# update all dependencies
go get -u ./...
# cleanup
go mod tidy
go mod verify
```
