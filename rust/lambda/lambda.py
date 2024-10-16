import logging
import base64
import boto3
import cfnresponse

log = logging.getLogger()
log.setLevel(logging.INFO)
kms = boto3.client("kms")
SUCCESS = "SUCCESS"
FAILED = "FAILED"


def handler(event, context):
    ciphertext = event["ResourceProperties"]["Ciphertext"]
    resource_id = event.get("LogicalResourceId")
    try:
        response_data = {
            "Plaintext": kms.decrypt(CiphertextBlob=base64.b64decode(ciphertext)).get("Plaintext").decode()
        }
        log.info("Decrypt successful")
        cfnresponse.send(event, context, SUCCESS, response_data, resource_id)
    except Exception as e:
        error_msg = f"Failed to decrypt: {repr(e)}"
        log.error(error_msg)
        cfnresponse.send(event, context, FAILED, dict(), resource_id)
        raise Exception(error_msg)
