const awscred = require('awscred');
const { promisify } = require('util');
const { CloudFormation } = require('aws-sdk');

const loadCredentialsAndRegion = promisify(awscred.loadCredentialsAndRegion);

module.exports = (options) => loadCredentialsAndRegion()
  .then(({ region }) => new CloudFormation({ region }).describeStacks({ StackName: options.vaultstack }).promise()
    .then((describeStackOutput) => Promise.resolve({ describeStackOutput, region })))
  .then(({ describeStackOutput, region }) => {
    const stack = describeStackOutput.Stacks[0];
    return Promise.resolve({
      vaultKey: options.k || stack.Outputs.find(output => output.OutputKey === 'kmsKeyArn').OutputValue,
      bucketName: options.b || stack.Outputs.find(output => output.OutputKey === 'vaultBucketName').OutputValue,
      region,
    });
  });
