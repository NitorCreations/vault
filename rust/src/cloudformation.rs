use std::fmt;

use aws_sdk_cloudformation::operation::describe_stacks::DescribeStacksOutput;
use aws_sdk_cloudformation::types::{Output, StackStatus, StackSummary};

use crate::errors::VaultError;

#[derive(Debug, Clone, Default)]
/// Parameter values for Cloudformation resources.
pub struct CloudFormationParams {
    pub bucket_name: String,
    pub key_arn: Option<String>,
    pub stack_name: String,
}

#[derive(Debug, Clone, Default)]
/// Cloudformation stack status information.
pub struct CloudFormationStackData {
    pub bucket_name: Option<String>,
    pub key_arn: Option<String>,
    pub version: Option<u32>,
    pub status: Option<StackStatus>,
    pub status_reason: Option<String>,
}

pub struct CloudFormationStackSummary {
    pub stack_name: Option<String>,
    pub stack_id: Option<String>,
    pub template_description: Option<String>,
    pub stack_status: Option<StackStatus>,
    pub stack_status_reason: Option<String>,
}

impl CloudFormationParams {
    #[must_use]
    /// Create `CloudFormationParams` from owned values.
    pub const fn new(bucket_name: String, key_arn: Option<String>, stack_name: String) -> Self {
        Self {
            bucket_name,
            key_arn,
            stack_name,
        }
    }

    #[must_use]
    /// Create `CloudFormationParams` from references.
    pub fn from(bucket_name: &str, key_arn: Option<&str>, stack_name: &str) -> Self {
        Self {
            bucket_name: bucket_name.to_owned(),
            key_arn: key_arn.map(std::borrow::ToOwned::to_owned),
            stack_name: stack_name.to_owned(),
        }
    }

    /// Get `CloudFormationParams` from Cloudformation describe stack output.
    pub async fn from_stack(
        client: &aws_sdk_cloudformation::Client,
        stack: String,
    ) -> Result<Self, VaultError> {
        let describe_stack_output = client
            .describe_stacks()
            .stack_name(stack.clone())
            .send()
            .await?;

        let stack_output = describe_stack_output
            .stacks()
            .first()
            .map(aws_sdk_cloudformation::types::Stack::outputs)
            .ok_or(VaultError::StackOutputsMissingError)?;

        let bucket_name = Self::parse_output_value_from_key("vaultBucketName", stack_output)
            .ok_or(VaultError::BucketNameMissingError)?;

        let key_arn = Self::parse_output_value_from_key("kmsKeyArn", stack_output);

        Ok(Self::new(bucket_name, key_arn, stack))
    }

    fn parse_output_value_from_key(key: &str, output: &[Output]) -> Option<String> {
        output
            .iter()
            .find(|output| output.output_key() == Some(key))
            .map(|output| output.output_value().unwrap_or_default().to_owned())
    }
}

impl fmt::Display for CloudFormationParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "bucket: {}\nkey: {}\nstack: {}",
            self.bucket_name,
            self.key_arn.as_ref().map_or("None", |k| k),
            self.stack_name
        )
    }
}

impl fmt::Display for CloudFormationStackData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "status: {}\nbucket: {}\nkey: {}\nversion: {}{}",
            self.status
                .as_ref()
                .map_or("None".to_string(), std::string::ToString::to_string),
            self.bucket_name.as_deref().unwrap_or("None"),
            self.key_arn.as_deref().unwrap_or("None"),
            self.version.map_or("None".to_string(), |v| v.to_string()),
            self.status_reason
                .as_ref()
                .map_or_else(String::new, |reason| format!("\nreason: {reason}"))
        )
    }
}

impl CloudFormationStackSummary {
    /// Create from AWS SDK `StackSummary`
    #[must_use]
    pub fn from_aws_stack_summary(stack: &StackSummary) -> Self {
        Self {
            stack_name: stack.stack_name().map(ToString::to_string),
            stack_id: stack.stack_id().map(ToString::to_string),
            template_description: stack.template_description().map(ToString::to_string),
            stack_status: stack.stack_status().cloned(),
            stack_status_reason: stack.stack_status_reason().map(ToString::to_string),
        }
    }
}

impl fmt::Display for CloudFormationStackSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "name: {}\nid: {}\ndescription: {}\nstatus: {}{}",
            self.stack_name.as_deref().unwrap_or("None"),
            self.stack_id.as_deref().unwrap_or("None"),
            self.template_description.as_deref().unwrap_or("None"),
            self.stack_status
                .as_ref()
                .map(|s| format!("{s:?}"))
                .as_deref()
                .unwrap_or("None"),
            self.stack_status_reason
                .as_ref()
                .map_or_else(String::new, |reason| format!("\nreason: {reason}"))
        )?;

        Ok(())
    }
}

/// Extract relevant information from Cloudformation stack outputs
pub async fn get_stack_data(
    cf_client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
) -> Result<CloudFormationStackData, VaultError> {
    let stack_response = describe_stack(cf_client, stack_name).await?;

    let mut data = CloudFormationStackData::default();
    if let Some(stacks) = stack_response.stacks {
        if let Some(stack) = stacks.first() {
            data.status.clone_from(&stack.stack_status);
            data.status_reason.clone_from(&stack.stack_status_reason);
            if let Some(outputs) = &stack.outputs {
                for output in outputs {
                    if let Some(output_key) = output.output_key() {
                        match output_key {
                            "vaultBucketName" => {
                                if let Some(output_value) = output.output_value() {
                                    data.bucket_name = Some(output_value.to_string());
                                }
                            }
                            "kmsKeyArn" => {
                                if let Some(output_value) = output.output_value() {
                                    data.key_arn = Some(output_value.to_string());
                                }
                            }
                            "vaultStackVersion" => {
                                if let Some(output_value) = output.output_value() {
                                    if let Ok(version) = output_value.parse::<u32>() {
                                        data.version = Some(version);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    Ok(data)
}

#[inline]
// Get Cloudformation describe stack output.
pub async fn describe_stack(
    cf_client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
) -> Result<DescribeStacksOutput, VaultError> {
    cf_client
        .describe_stacks()
        .stack_name(stack_name)
        .send()
        .await
        .map_err(VaultError::from)
}

/// List all vault stacks
///
/// Stacks are identified by the description set by the Cloudformation template.
pub async fn list_stacks(
    cf_client: &aws_sdk_cloudformation::Client,
) -> Result<Vec<CloudFormationStackSummary>, VaultError> {
    let mut stacks = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let response = cf_client
            .list_stacks()
            .set_next_token(next_token.clone())
            .send()
            .await?;

        stacks.extend(
            response
                .stack_summaries()
                .iter()
                .filter(|summary| {
                    summary.stack_status.as_ref().is_some_and(|status| {
                        *status != StackStatus::DeleteComplete
                            && *status != StackStatus::DeleteInProgress
                    })
                })
                .filter(|&summary| {
                    summary.template_description().is_some_and(|description| {
                        description.eq_ignore_ascii_case("nitor vault stack")
                    }) || summary
                        .stack_name()
                        .is_some_and(|name| name.eq_ignore_ascii_case("vault"))
                })
                .map(CloudFormationStackSummary::from_aws_stack_summary),
        );

        next_token = response.next_token().map(ToString::to_string);
        if next_token.is_none() {
            break;
        }
    }

    Ok(stacks)
}
