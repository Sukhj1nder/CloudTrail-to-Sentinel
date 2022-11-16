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

### Setup and Deploy
1. In Microsoft Sentinel, select Data connectors and then select the Amazon Web Services S3 line in the table and in the AWS pane to the right, select Open connector page. Under Configuration, copy the External ID (Workspace ID) and paste it aside.
2. Run a cdk bootstrap on all the accounts that you are deploying resources to which includes all accounts you're retrieving logs for and the centralized logging account e.g. cdk bootstrap aws://123456789012/us-east-1 will bootstrap account 123456789012 in the us-east-1 region as long as you have permissions to do so in your CLI context. This is to create the required roles to allow cdk to deploy
3. Checkout the code from the github repo and run pip install -r requirements.txt in the cli under the sentinel and sentinel_lambda directories ie. cd sentinel and cd sentinel_lambda first
4. We are going to deploy the stack to integrate with sentinel first which will go into the centralized logging account. In the sentinel directory from the checked out code, edit the cdk.json file and change the account-id field to the account number of your centralized logging account, change all_accounts field to include all the accounts you're collecting logs from and change the sentinel_worskpace_id field to the ID copied from the first step
5. In the sentinel directory, run an optional cdk synth to check that everything is valid and compiles to cloudfornation followed by cdk deploy to deploy the stack to the centralized logging account
6. After the stack has been deployed, you will see a number of outputs from the cloudformation . Take note of the SentinelRoleArn and SentinelQueueURL output fields to be used in the next step and SentinelBucketArn and SentinelBucketName fields to be used in later steps
7. In Microsoft Sentinel, go to the AWS S3 connector page and under Add connection:
a. Paste the IAM role ARN (SentinelRoleArn) into the Role ARN field
b. Paste the URL of the SQS queue (SentinelQueueURL) into the SQS URL field
c. Select CloudTrail from the Destination table drop-down list
d. Select Add connection
8. Now that Sentinel has been integrated, we are going to deploy the Lambda stack in each account we want to collect logs from. In the sentinel_lambda directory from the checked out code, edit the cdk.json file and change the bucket_name and bucket_arn fields to the SentinelBucketName and SentinelBucketArn outputs from step 6 respectively. Change log_group_name to the name of the cloudwatch log group you wish to fetch logs from which should be the same across all accounts. This has been set to aws-controltower/CloudTrailLogs by default as this is the name that Control Tower gives to the cloudtrail trail log group. Change the account-id fields to the account numbers of all accounts to collect logs from. You can call the parent node whatever you want e.g. currently set to audit, logging and billing
9. Optionally modify the filter_pattern in lambda_stack.py to modify the sources from which you want to collect cloudtrail logs from. By default we are auditing from services signin.amazonaws.com, sso.amazonaws.com, wafv2.amazonaws.com, secretsmanager.amazonaws.com, guardduty.amazonaws.com, route53.amazonaws.com, iam.amazonaws.com
10. In the sentinel_lambda directory, run an optional cdk synth --context stage=[stageName] e.g. cdk synth --context stage=auditto check that everything is valid and compiles to cloudfornation followed by cdk deploy --context stage=[stageName] to deploy the stack to the targetted account and repeat for each stageName to deploy across other accounts

Refer to https://medium.com/@geoff1337/filtered-aws-cloudtrail-logs-ingestion-to-microsoft-sentinel-ee1cc5b516b0 for more detailed info
