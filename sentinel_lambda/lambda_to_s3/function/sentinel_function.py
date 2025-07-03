import os
import gzip
import json
import base64
from datetime import datetime, timezone, timedelta
import boto3
import logging
from typing import Dict, Any, List

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda function that runs every 2 hours to scan CloudTrail logs from CloudWatch
    and forward filtered events to S3 bucket for Sentinel ingestion.
    
    Args:
        event: EventBridge scheduled event
        context: Lambda context object
        
    Returns:
        Dict containing status code and response body
    """
    
    logger.info("Starting scheduled CloudTrail log processing (2-hour interval)")
    
    # Get configuration from environment
    s3_bucket = os.environ.get("S3_BUCKET")
    scan_interval_hours = int(os.environ.get("SCAN_INTERVAL_HOURS", "2"))
    log_group_name = os.environ.get("LOG_GROUP_NAME", "aws-controltower/CloudTrailLogs")
    
    if not s3_bucket:
        logger.error("No S3 bucket specified in environment variables")
        return {
            "statusCode": 500, 
            "body": json.dumps({"error": "Missing S3_BUCKET environment variable"})
        }

    # Calculate time range for scanning (last 2 hours + 5 minute buffer)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=scan_interval_hours, minutes=5)
    
    logger.info(f"Scanning CloudTrail logs from {start_time.isoformat()} to {end_time.isoformat()}")
    
    try:
        # Query CloudWatch Logs for events in the time range
        logs_client = boto3.client('logs')
        
        # Filter pattern for security-relevant events
        filter_pattern = ('{ $.eventSource = "signin.amazonaws.com" '
                         '|| $.eventSource = "sso.amazonaws.com" '
                         '|| $.eventSource = "wafv2.amazonaws.com" '
                         '|| $.eventSource = "secretsmanager.amazonaws.com" '
                         '|| $.eventSource = "guardduty.amazonaws.com" '
                         '|| $.eventSource = "route53.amazonaws.com" '
                         '|| $.eventSource = "iam.amazonaws.com" }')
        
        # Convert to milliseconds for AWS API
        start_time_ms = int(start_time.timestamp() * 1000)
        end_time_ms = int(end_time.timestamp() * 1000)
        
        # Scan CloudWatch Logs
        all_events = []
        next_token = None
        
        while True:
            try:
                if next_token:
                    response = logs_client.filter_log_events(
                        logGroupName=log_group_name,
                        startTime=start_time_ms,
                        endTime=end_time_ms,
                        filterPattern=filter_pattern,
                        nextToken=next_token,
                        limit=1000  # Process in batches
                    )
                else:
                    response = logs_client.filter_log_events(
                        logGroupName=log_group_name,
                        startTime=start_time_ms,
                        endTime=end_time_ms,
                        filterPattern=filter_pattern,
                        limit=1000
                    )
                
                events = response.get('events', [])
                all_events.extend(events)
                
                logger.info(f"Retrieved {len(events)} events in this batch, total: {len(all_events)}")
                
                # Check if there are more events
                next_token = response.get('nextToken')
                if not next_token:
                    break
                    
            except Exception as e:
                logger.error(f"Error querying CloudWatch Logs: {e}")
                break
        
        if not all_events:
            logger.info("No events found in the specified time range")
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No events found in scheduled scan",
                    "timeRange": f"{start_time.isoformat()} to {end_time.isoformat()}",
                    "eventsProcessed": 0
                })
            }
        
        # Process and filter the events
        valid_records = []
        invalid_count = 0
        
        for event in all_events:
            try:
                # Parse the CloudTrail record to validate it's proper JSON
                ct_record = json.loads(event['message'])
                
                # Additional filtering can be done here if needed
                event_source = ct_record.get('eventSource', '')
                event_name = ct_record.get('eventName', '')
                
                # Optional: Filter out read-only events for reduced volume
                # if ct_record.get('readOnly', False):
                #     continue
                
                valid_records.append(event['message'])
                
            except (json.JSONDecodeError, KeyError) as e:
                invalid_count += 1
                logger.debug(f"Skipped invalid CloudTrail record: {e}")
                continue
        
        logger.info(f"Processed {len(all_events)} total events, {len(valid_records)} valid records, {invalid_count} invalid")
        
        if not valid_records:
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No valid CloudTrail records found",
                    "totalEvents": len(all_events),
                    "validRecords": 0
                })
            }
        
        # Upload to S3 in batches if needed (to handle large volumes)
        batch_size = 1000  # Adjust based on Lambda memory and timeout
        upload_results = []
        
        for i in range(0, len(valid_records), batch_size):
            batch = valid_records[i:i + batch_size]
            result = upload_batch_to_s3(batch, s3_bucket, i // batch_size + 1, start_time, end_time)
            upload_results.append(result)
        
        # Summary of results
        total_uploaded = sum(r.get('recordsUploaded', 0) for r in upload_results)
        
        logger.info(f"Successfully processed {total_uploaded} records in {len(upload_results)} batch(es)")
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Successfully processed scheduled CloudTrail logs",
                "timeRange": f"{start_time.isoformat()} to {end_time.isoformat()}",
                "totalEventsScanned": len(all_events),
                "validRecordsFound": len(valid_records),
                "recordsUploaded": total_uploaded,
                "batchesUploaded": len(upload_results),
                "uploadResults": upload_results
            })
        }
        
    except Exception as error:
        logger.error(f"Error in scheduled CloudTrail processing: {error}")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": f"Scheduled processing failed: {str(error)}",
                "timeRange": f"{start_time.isoformat()} to {end_time.isoformat()}"
            })
        }

def upload_batch_to_s3(records: List[str], s3_bucket: str, batch_number: int, 
                      start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    """Upload a batch of CloudTrail records to S3"""
    
    try:
        # Create CloudTrail Records format
        records_json = f'{{"Records":[{",".join(records)}]}}'
        
        # Generate S3 key path following CloudTrail convention
        now = datetime.now(timezone.utc)
        s3_key = (
            f"AWSLogs/scheduled/CloudTrail/"
            f"{now.year:04d}/{now.month:02d}/{now.day:02d}/"
            f"scheduled_CloudTrail_batch{batch_number:03d}_{now.strftime('%Y%m%d_%H%M%S')}.json.gz"
        )
        
        # Upload to S3
        s3_client = boto3.client("s3")
        compressed_data = gzip.compress(records_json.encode('utf-8'))
        
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=s3_key,
            Body=compressed_data,
            ContentEncoding="gzip",
            ContentType="application/json",
            Metadata={
                "source": "cloudtrail-lambda-scheduled",
                "recordCount": str(len(records)),
                "batchNumber": str(batch_number),
                "scanStartTime": start_time.isoformat(),
                "scanEndTime": end_time.isoformat(),
                "processedAt": now.isoformat(),
                "processingMode": "scheduled-2hour"
            },
            ServerSideEncryption="AES256"
        )
        
        logger.info(f"Uploaded batch {batch_number} with {len(records)} records to s3://{s3_bucket}/{s3_key}")
        
        return {
            "batchNumber": batch_number,
            "recordsUploaded": len(records),
            "s3Key": s3_key,
            "status": "success"
        }
        
    except Exception as error:
        logger.error(f"Failed to upload batch {batch_number} to S3: {error}")
        return {
            "batchNumber": batch_number,
            "recordsUploaded": 0,
            "error": str(error),
            "status": "failed"
        }