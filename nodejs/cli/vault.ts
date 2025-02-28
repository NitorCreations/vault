#!/usr/bin/env node
import { Command } from "commander";
import { vault } from "../lib/vaultClient";

// Hack to support flags for commands to match CLI interface for other implementations
const commandAliases: Record<string, string> = {
  "-s": "store",
  "--store": "store",
  "-l": "lookup",
  "--lookup": "lookup",
  "-d": "delete",
  "--delete": "delete",
  "-e": "exists",
  "--exists": "exists",
  "-a": "all",
  "--all": "all",
};
const modifiedArgs = process.argv.map(arg => commandAliases[arg] || arg);

async function storeCommand(name: string, value: string | undefined, options: any) {
  try {
    const storeValue = value || options.value;
    if (!storeValue) {
      console.error("Error: A value must be provided either as an argument or with -v");
      process.exit(1);
    }

    const client = await vault(options);
    if (!options.overwrite && await client.exists(name)) {
      console.log("Error: Key already exists. Use \x1b[33m-w\x1b[0m to overwrite.");
      return;
    }
    await client.store(name, storeValue);
  } catch (error) {
    handleRejection(error);
  }
}

async function lookupCommand(name: string, options: any) {
  try {
    const client = await vault(options);
    const result = await client.lookup(name);
    process.stdout.write(result);
  } catch (error) {
    handleRejection(error);
  }
}

async function deleteCommand(name: string, options: any) {
  try {
    const client = await vault(options);
    await client.delete(name);
  } catch (error) {
    handleRejection(error);
  }
}

async function existsCommand(name: string, options: any) {
  try {
    const client = await vault(options);
    const exists = await client.exists(name);
    console.log(`key '${name}' ${exists ? "exists" : "does not exist"}`);
  } catch (error) {
    handleRejection(error);
  }
}

async function allCommand(options: any) {
  try {
    const client = await vault(options);
    const keys = await client.all();
    console.log(keys.join("\n"));
  } catch (error) {
    handleRejection(error);
  }
}

function handleRejection(err: unknown) {
  if (err instanceof Error) {
    console.error(err.message);
  } else {
    console.error("An unknown error occurred:", err);
  }
  process.exit(1);
}

const program = new Command();

program.version("2.0.0");

program
  .option("--vaultstack <stack>", "Optional CloudFormation stack to lookup key and bucket")
  .option("-p, --prefix <prefix>", "Optional prefix to store values under")
  .option("-b, --bucket <bucket>", "Override the bucket name")
  .option("-k, --key-arn <arn>", "Override the KMS key ARN")
  .option("--id <id>", "Override IAM access key ID")
  .option("--secret <secret>", "Override IAM secret access key")
  .option("-r, --region <region>", "Specify the AWS region");

program
  .command("store <name> [value]")
  .alias("s")
  .description("Store data in the vault")
  .option("-w, --overwrite", "Overwrite the existing value", false)
  .option("-v, --value <value>", "Value to store")
  .action(storeCommand);

program
  .command("lookup <name>")
  .alias("l")
  .description("Look up data from the vault")
  .action(lookupCommand);

program
  .command("delete <name>")
  .alias("d")
  .description("Delete data from the vault")
  .action(deleteCommand);

program
  .command("exists <name>")
  .alias("e")
  .description("Check if the vault contains data")
  .action(existsCommand);

program
  .command("all")
  .alias("a")
  .description("List all keys the vault contains")
  .action(allCommand);

program.parse(modifiedArgs);
