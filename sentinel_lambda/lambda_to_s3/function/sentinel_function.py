import os
import gzip
import json
import base64
from datetime import datetime, timezone
import boto3
import logging
from typing import Dict, Any, List

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda function to process CloudTrail logs from CloudWatch Logs
    and forward filtered events to S3 bucket for Sentinel ingestion.
    
    Args:
        event: CloudWatch Logs event data
        context: Lambda context object
        
    Returns:
        Dict containing status code and response body
    """
    
    # Get S3 bucket name from environment
    s3_bucket = os.environ.get("S3_BUCKET")
    if not s3_bucket:
        logger.error("No S3 bucket specified in environment variables")
        return {
            "statusCode": 500, 
            "body": json.dumps({"error": "Missing S3_BUCKET environment variable"})
        }

    try:
        # Decode and decompress CloudWatch Logs data
        compressed_data = event["awslogs"]["data"]
        compressed_payload = base64.b64decode(compressed_data)
        uncompressed_payload = gzip.decompress(compressed_payload)
        log_data = json.loads(uncompressed_payload.decode('utf-8'))
        
        logger.info(f"Processing {len(log_data.get('logEvents', []))} log events")
        
    except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as error:
        logger.error(f"Failed to decode CloudWatch Logs data: {error}")
        return {
            "statusCode": 400, 
            "body": json.dumps({"error": f"Failed to decode log data: {str(error)}"})
        }
    except Exception as error:
        logger.error(f"Unexpected error during data decoding: {error}")
        return {
            "statusCode": 500, 
            "body": json.dumps({"error": f"Unexpected error: {str(error)}"})
        }

    # Process log events
    records: List[str] = []
    region = "default"
    
    for log_event in log_data.get("logEvents", []):
        message = log_event.get("message", "")
        if not message.strip():
            continue
            
        try:
            # Parse the CloudTrail record to validate it's proper JSON
            ct_record = json.loads(message)
            
            # Get region from first valid record
            if region == "default" and "awsRegion" in ct_record:
                region = ct_record["awsRegion"]
            
            records.append(message)
                
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse CloudTrail record: {e}")
            continue
        except Exception as e:
            logger.warning(f"Unexpected error processing log event: {e}")
            continue

    # If no valid records, return success (nothing to process)
    if not records:
        logger.info("No valid CloudTrail records to process")
        return {
            "statusCode": 200, 
            "body": json.dumps({"message": "No records to process", "recordsProcessed": 0})
        }

    # Create CloudTrail Records format
    records_json = f'{{"Records":[{",".join(records)}]}}'
    
    # Generate S3 key path following CloudTrail convention
    now = datetime.now(timezone.utc)
    owner = log_data.get("owner", "unknown")
    
    # Format: AWSLogs/{account}/CloudTrail/{region}/{year}/{month}/{day}/{filename}
    s3_key = (
        f"AWSLogs/{owner}/CloudTrail/{region}/"
        f"{now.year:04d}/{now.month:02d}/{now.day:02d}/"
        f"{owner}_CloudTrail_{region}_{now.strftime('%Y%m%d_%H%M%S_%f')}.json.gz"
    )
    
    try:
        # Upload to S3 using client (more efficient than resource for this use case)
        s3_client = boto3.client("s3")
        
        # Compress the data
        compressed_data = gzip.compress(records_json.encode('utf-8'))
        
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=s3_key,
            Body=compressed_data,
            ContentEncoding="gzip",
            ContentType="application/json",
            Metadata={
                "source": "cloudtrail-lambda-forwarder",
                "recordCount": str(len(records)),
                "region": region,
                "processedAt": now.isoformat()
            },
            ServerSideEncryption="AES256"  # Ensure encryption at rest
        )
        
        logger.info(f"Successfully uploaded {len(records)} records to s3://{s3_bucket}/{s3_key}")
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Successfully processed CloudTrail logs",
                "recordsProcessed": len(records),
                "s3Key": s3_key,
                "s3Bucket": s3_bucket
            })
        }
        
    except boto3.exceptions.S3UploadFailedError as error:
        logger.error(f"S3 upload failed: {error}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": f"S3 upload failed: {str(error)}"})
        }
    except Exception as error:
        logger.error(f"Unexpected error during S3 upload: {error}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": f"Failed to upload to S3: {str(error)}"})
        }