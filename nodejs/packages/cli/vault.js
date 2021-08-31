#!/usr/bin/env node
const sade = require('sade');
const loadOptions = require('../lib/loadOptions');
const client = require('../lib/vaultClient');

const DEFAULT_STACK_NAME = 'vault';

const handleRejection = err => {
  console.error(err);
  process.exit(1);
};

const prog = sade('vault');

prog.option('--vaultstack', 'Optional CloudFormation stack to lookup key and bucket.', DEFAULT_STACK_NAME);
prog.option('-p, --prefix', 'Optional prefix to store values under. Empty by default');
prog.option('-b, --bucket', 'Override the bucket name either for initialization or storing and looking up values');
prog.option('-k, --key-arn', 'Override the KMS key arn for storing or looking up values');
prog.option('--id', 'Give an IAM access key id to override those defined by the environment');
prog.option('--secret', 'Give an IAM secret access key to override those defined by the environment');
prog.option('-r, --region', 'Give a region for the stack and the bucket');

prog
  .command('store <name> <value>')
  .describe('Store data in the vault')
  .option('-w, --overwrite', 'Overwrite the current value if it already exists', false)
  .action((name, value, options) => {
    loadOptions(options)
      .then(options => client.store(name, value, options))
      .catch(handleRejection);
  })
  .command('lookup <name>')
  .describe('Look up data from the vault')
  .action((name, options) => {
    loadOptions(options)
      .then(options => client.lookup(name, options))
      .then(console.log)
      .catch(handleRejection);
  })
  .command('delete <name>')
  .describe('Delete data from the vault')
  .action((name, options) => {
    loadOptions(options)
      .then(options => client.delete(name, options))
      .catch(handleRejection)
  })
  .command('exists <name>')
  .describe('Check if the vault contains data')
  .action((name, options) => {
    loadOptions(options)
      .then(options => client.exists(name, options))
      .then(console.log)
      .catch(handleRejection)
  })
  .command('all')
  .describe('List all keys the vault contains')
  .action(options => {
    loadOptions(options)
      .then(options => client.all(options))
      .then(console.log)
      .catch(handleRejection)
  });

prog.parse(process.argv);
