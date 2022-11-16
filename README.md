# cloudtrail-to-sentinel
CDK Python Project for centralized AWS CloudTrail logging to Microsoft Sentinel

## Sentinel

An s3 bucket is created to store all the logs going to Sentinel Azure
An SQS queue is created for the s3 bucket to integrate with event notifications
on s3 object create events. A role is also created.

Sentinel on premises then makes use of the sqs endpoint url and role arn
to poll the queue which receives messages when objects in s3 are created.
It will then ingest the objects in s3 (cloud trail logs).

### Configuration

`cdk.json` contains the details of the sentinel workspace id which is
derived from sentinel.

## Sentinel Lambda

A lambda function is created to send all the filtered cloudtrail logs
to the s3 bucket in the sentinel stack. This needs to be created on all
the accounts to send the filtered cloudtrail logs to the s3 bucket
in the log archive account

### Configuration

`cdk.json` contains the details of the s3 bucket name/arn which is
derived from the sentinel stack after it is created

