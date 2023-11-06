# Nitor Vault (Go Version)

A command line tool for encrypting and decrypting keys and values using client-side encryption with AWS KMS keys, implemented in Go.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- You have installed the latest version of [Go](https://go.dev/).
- You have an AWS account with permissions to access AWS KMS, S3, and CloudFormation services.
- You have configured AWS credentials that the tool can use to access AWS services.

## Building the Tool

To build the `nitor-vault` tool, follow these steps:

```shell
go build -o nitor-vault ./cmd/nitor_vault
```

## Format code

Using [gofmt](https://pkg.go.dev/cmd/gofmt)

```shell
gofmt -s -w .
```
