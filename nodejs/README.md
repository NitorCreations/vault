# nitor-vault

Node.js library for storing encrypting keys and values securely to AWS infrastructure.

## Requirements

- [Node.js](https://nodejs.org/)
- [pnpm](https://pnpm.io/)

## Install dependencies

```shell
pnpm install
```

For reproducible installs (e.g. in CI):

```shell
pnpm install --frozen-lockfile
```

## Build

Compile TypeScript sources to `dist/`:

```shell
pnpm build
```

## Run

Run the CLI directly from sources (without building) using `tsx`:

```shell
pnpm vault --help
```

After building, you can run the compiled CLI:

```shell
node dist/cli/vault.js --help
```

## Licence

[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)
