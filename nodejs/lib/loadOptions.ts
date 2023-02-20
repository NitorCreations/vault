import { CloudFormation } from "aws-sdk";

interface OptionsInput {
  vaultstack: string | undefined;
  k: string | undefined;
  b: string | undefined;
  r: string | undefined;
}
export const loadOptions = async (options: OptionsInput) => {
  const describeStackOutput = await new CloudFormation({ region: options.r })
    .describeStacks({ StackName: options.vaultstack })
    .promise();
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
