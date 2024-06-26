import { CloudFormation } from "@aws-sdk/client-cloudformation";

export interface OptionsInput {
  vaultstack?: string;
  k?: string;
  b?: string;
  r?: string;
}

const DEFAULT_STACK_NAME = "vault";

export const loadOptions = async (options: OptionsInput) => {
  const describeStackOutput = await new CloudFormation({
    region: options.r,
  }).describeStacks({
    StackName:
      options.vaultstack || process.env.VAULT_STACK || DEFAULT_STACK_NAME,
  });
  const { describeStackOutput: describeStackOutput_1 } = await Promise.resolve({
    describeStackOutput,
  });
  const stack = describeStackOutput_1.Stacks![0];
  return await Promise.resolve({
    vaultKey:
      options.k ||
      stack.Outputs?.find((output) => output.OutputKey === "kmsKeyArn")
        ?.OutputValue ||
      "",
    bucketName:
      options.b ||
      stack.Outputs?.find(
        (output_1) => output_1.OutputKey === "vaultBucketName"
      )?.OutputValue ||
      "",
    region: options.r,
  });
};
export type Options = Awaited<ReturnType<typeof loadOptions>>;
