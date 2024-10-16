use std::collections::HashMap;

use aws_lambda_events::cloudformation::{
    CloudFormationCustomResourceResponse, CloudFormationCustomResourceResponseStatus,
};
use aws_lambda_events::event::cloudformation::CloudFormationCustomResourceRequest;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::Client as KmsClient;
use base64::{engine::general_purpose, Engine};
use lambda_runtime::{run, service_fn, tracing, Error, LambdaEvent};
use reqwest::Client as HttpClient;
use serde_json::Value;
use tracing::{error, info};

struct EventData {
    logical_resource_id: String,
    physical_resource_id: String,
    request_id: String,
    stack_id: String,
    response_url: String,
}

async fn function_handler(
    event: LambdaEvent<CloudFormationCustomResourceRequest>,
) -> Result<(), Error> {
    let (resource_properties, event_data) = extract_event_data(event);

    let config = aws_config::load_from_env().await;
    let kms_client = KmsClient::new(&config);

    // Parse the ciphertext from the CloudFormation request
    let ciphertext = if let Some(ciphertext) = resource_properties.get("Ciphertext") {
        ciphertext.to_string()
    } else {
        let error_message = "Ciphertext missing".to_string();
        error!("{error_message}");
        return send_response(
            event_data,
            CloudFormationCustomResourceResponseStatus::Failed,
            None,
            Some(error_message),
        )
        .await;
    };

    // Try to decrypt the ciphertext using KMS
    match decrypt_ciphertext(&kms_client, &ciphertext).await {
        Ok(plaintext) => {
            let message = "Decrypt successful".to_string();
            info!(message);
            let response_data = HashMap::from([("Plaintext".to_string(), plaintext)]);
            send_response(
                event_data,
                CloudFormationCustomResourceResponseStatus::Success,
                Some(response_data),
                Some(message),
            )
            .await
        }
        Err(e) => {
            let error_message = format!("Failed to decrypt: {e:?}");
            error!("{error_message}");
            send_response(
                event_data,
                CloudFormationCustomResourceResponseStatus::Failed,
                None,
                Some(error_message),
            )
            .await
        }
    }
}

fn extract_event_data(
    event: LambdaEvent<CloudFormationCustomResourceRequest>,
) -> (Value, EventData) {
    let (request, context) = event.into_parts();
    match request {
        CloudFormationCustomResourceRequest::Create(create_request) => (
            create_request.resource_properties,
            EventData {
                logical_resource_id: create_request.logical_resource_id,
                physical_resource_id: context.env_config.log_stream.clone(),
                request_id: create_request.request_id,
                stack_id: create_request.stack_id,
                response_url: create_request.response_url,
            },
        ),
        CloudFormationCustomResourceRequest::Update(update_request) => (
            update_request.resource_properties,
            EventData {
                logical_resource_id: update_request.logical_resource_id,
                physical_resource_id: update_request.physical_resource_id,
                request_id: update_request.request_id,
                stack_id: update_request.stack_id,
                response_url: update_request.response_url,
            },
        ),
        CloudFormationCustomResourceRequest::Delete(delete_request) => (
            delete_request.resource_properties,
            EventData {
                logical_resource_id: delete_request.logical_resource_id,
                physical_resource_id: delete_request.physical_resource_id,
                request_id: delete_request.request_id,
                stack_id: delete_request.stack_id,
                response_url: delete_request.response_url,
            },
        ),
    }
}

/// Decrypt a base64-encoded ciphertext using AWS KMS.
async fn decrypt_ciphertext(kms_client: &KmsClient, ciphertext: &str) -> Result<String, Error> {
    let decoded_ciphertext = general_purpose::STANDARD.decode(ciphertext)?;

    // Decrypt the ciphertext using KMS
    let response = kms_client
        .decrypt()
        .ciphertext_blob(Blob::new(decoded_ciphertext))
        .send()
        .await?;

    // Convert the decrypted plaintext to a string
    let plaintext = match response.plaintext {
        None => return Err("Plaintext is missing in the response".into()),
        Some(blob) => blob.into_inner(),
    };

    // TODO: does this need to support binary data?
    Ok(String::from_utf8(plaintext)?)
}

/// Sends a response to the `CloudFormation` `ResponseURL`
async fn send_response(
    event: EventData,
    status: CloudFormationCustomResourceResponseStatus,
    data: Option<HashMap<String, String>>,
    reason: Option<String>,
) -> Result<(), Error> {
    let http_client = HttpClient::new();

    let response = CloudFormationCustomResourceResponse {
        status,
        reason,
        physical_resource_id: event.physical_resource_id,
        stack_id: event.stack_id,
        request_id: event.request_id,
        logical_resource_id: event.logical_resource_id,
        no_echo: false,
        data: data.unwrap_or_default(),
    };

    http_client
        .put(&event.response_url)
        .json(&response)
        .send()
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();
    run(service_fn(function_handler)).await
}
