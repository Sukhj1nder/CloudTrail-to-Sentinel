from dataclasses import dataclass

# from typing import Union, Literal
from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_sqs as sqs,
    aws_kms as kms,
    aws_s3 as s3,
    aws_s3_notifications as s3n,
    Duration,
    CfnOutput,
)
import aws_cdk as cdk
from cdk_nag import NagSuppressions, NagPackSuppression

from constructs import Construct


@dataclass
class SentinelProps:
    sentinel_worskpace_id: str
    sentinel_account_id: str
    all_accounts: list[str]


class SentinelStack(Stack):
    """Generate the Sentinel AWS infrastructure. S3 Bucket, SQS queue for cloudtrail logs and role with policies for sentinel to assume"""

    def __init__(
        self, scope: Construct, construct_id: str, props: SentinelProps, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # key for queue encryption
        self.sqs_key = kms.Key(
            self,
            "sentinel_queue_key",
            enable_key_rotation=True,
            description="Key used for sentinel sqs queue",
        )

        # dlq for sentinel queue
        self.sentinel_sqs_dlq = sqs.Queue(self, "sentinel_sqs_dlq")
        dead_letter_queue_settings = sqs.DeadLetterQueue(
            max_receive_count=10, queue=self.sentinel_sqs_dlq
        )

        # queue for sentinel to consume
        self.sentinel_sqs_queue = sqs.Queue(
            self,
            "sentinel_queue",
            receive_message_wait_time=Duration.seconds(20),
            retention_period=Duration.days(1),
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=self.sqs_key,
            dead_letter_queue=dead_letter_queue_settings,
        )

        # role for sentinel to assume
        self.sentinel_role = iam.Role(
            self,
            "sentinel_role",
            assumed_by=iam.AccountPrincipal(props.sentinel_account_id),
            description="Role for sentinel to ingest logs from s3 and check sqs queue for messages",
            external_ids=[props.sentinel_worskpace_id],
            role_name="AWSSentinelRole",
        )

        # allow sentinel queue to send to dlq
        self.sentinel_sqs_dlq.add_to_resource_policy(
            iam.PolicyStatement(
                sid="SQS-Sentinel",
                actions=["SQS:SendMessage"],
                principals=[iam.ServicePrincipal("sqs.amazonaws.com")],
                resources=[self.sentinel_sqs_dlq.queue_arn],
                conditions={
                    "ArnLike": {"aws:SourceArn": self.sentinel_sqs_queue.queue_arn}
                },
            )
        )

        # Bucket for S3 access logging. This bucket can't be logged and must be
        # encrypted with S3 encryption, KMS encryption won't work
        self.s3_access_log_bucket = s3.Bucket(
            self,
            "s3_access_logs",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,  # Allow ACLs for logging
            lifecycle_rules=[
                s3.LifecycleRule(enabled=True, expiration=Duration.days(30))
            ],
        )
        self.s3_access_log_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="S3ServerAccessLogs",
                actions=["s3:PutObject"],
                principals=[iam.ServicePrincipal("logging.s3.amazonaws.com")],
                resources=[self.s3_access_log_bucket.arn_for_objects(key_pattern="*")],
                conditions={"StringEquals": {"aws:SourceAccount": self.account}},
            )
        )
        NagSuppressions.add_resource_suppressions(
            self.s3_access_log_bucket,
            [
                NagPackSuppression(
                    id="AwsSolutions-S1",
                    reason="This is the S3 access log destination bucket.",
                )
            ],
            True,
        )

        # Bucket for sentinel logging from lambdas across accounts. Retain for 365 days.
        self.sentinel_bucket = s3.Bucket(
            self,
            "sentinel_bucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            server_access_logs_bucket=self.s3_access_log_bucket,
            versioned=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,  # Changed from BUCKET_OWNER_ENFORCED
            lifecycle_rules=[
                s3.LifecycleRule(enabled=True, expiration=Duration.days(365))
            ],
        )
        # object created event notification for sqs queue
        self.sentinel_bucket.add_object_created_notification(
            s3n.SqsDestination(self.sentinel_sqs_queue)
        )
        # allow services to access bucket
        accountArns = [iam.ArnPrincipal(f"arn:aws:iam::{a}:root") for a in props.all_accounts]
        principals = [
            iam.ServicePrincipal("logging.s3.amazonaws.com"),
            iam.ServicePrincipal("lambda.amazonaws.com"),
            iam.ServicePrincipal("events.amazonaws.com"),
            iam.ServicePrincipal("config.amazonaws.com"),
            iam.ServicePrincipal("logs.amazonaws.com"),
        ] + accountArns
        self.sentinel_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="S3AllowServices",
                actions=["s3:GetBucketAcl", "s3:ListBucket", "s3:PutObject"],
                principals=principals,
                resources=[
                    self.sentinel_bucket.bucket_arn,
                    self.sentinel_bucket.arn_for_objects(key_pattern="*"),
                ],
            )
        )
        # allow sentinel role to retrieve from bucket
        self.sentinel_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="S3AllowSentinelRole",
                actions=["s3:GetObject", "s3:ListBucket"],
                principals=[iam.ArnPrincipal(self.sentinel_role.role_arn)],
                resources=[
                    self.sentinel_bucket.bucket_arn,
                    self.sentinel_bucket.arn_for_objects(key_pattern="*")
                ],
            )
        )

        NagSuppressions.add_stack_suppressions(
            self,
            [
                NagPackSuppression(
                    id="AwsSolutions-IAM4", reason="Ok to use managed policy."
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5", reason="Ok for wildcard permissions."
                ),
            ],
            True,
        )

        # allow s3 bucket to send to queue
        self.sentinel_sqs_queue.add_to_resource_policy(
            iam.PolicyStatement(
                sid="SQS-S3-Notifications",
                actions=["SQS:SendMessage"],
                principals=[iam.ServicePrincipal("s3.amazonaws.com")],
                resources=[self.sentinel_sqs_queue.queue_arn],
                conditions={
                    "ArnLike": {"aws:SourceArn": self.sentinel_bucket.bucket_arn}
                },
            )
        )

        # allow sentinel to consume from queue
        self.sentinel_sqs_queue.add_to_resource_policy(
            iam.PolicyStatement(
                sid="SQS-Sentinel-Receive",
                actions=[
                    "SQS:ChangeMessageVisibility",
                    "SQS:DeleteMessage",
                    "SQS:ReceiveMessage",
                    "SQS:GetQueueUrl",
                ],
                principals=[iam.ArnPrincipal(self.sentinel_role.role_arn)],
                resources=[self.sentinel_sqs_queue.queue_arn],
            )
        )

        NagSuppressions.add_resource_suppressions(
            self.sentinel_sqs_queue,
            [
                NagPackSuppression(id="AwsSolutions-SQS3", reason="DLQ not required"),
                NagPackSuppression(
                    id="AwsSolutions-SQS4", reason="SSL maybe enforced later"
                ),
            ],
            True,
        )
        NagSuppressions.add_resource_suppressions(
            self.sentinel_sqs_dlq,
            [
                NagPackSuppression(
                    id="AwsSolutions-SQS2", reason="Encryption not required for dlq"
                ),
                NagPackSuppression(
                    id="AwsSolutions-SQS3", reason="DLQ not required for DLQ"
                ),
                NagPackSuppression(
                    id="AwsSolutions-SQS4", reason="SSL maybe enforced later"
                ),
            ],
            True,
        )

        # allow sentinel role to decrypt sqs kms key on kms policy
        self.sqs_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="Sentinel-Decrypt",
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                principals=[
                    iam.ArnPrincipal(self.sentinel_role.role_arn),
                    iam.ServicePrincipal("s3.amazonaws.com"),
                ],
                resources=["*"],
            )
        )

        # allow sentinel role to consume from queue
        self.sentinel_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "SQS:ChangeMessageVisibility",
                    "SQS:DeleteMessage",
                    "SQS:ReceiveMessage",
                    "SQS:GetQueueUrl",
                    "SQS:GetQueueAttributes",
                ],
                resources=[self.sentinel_sqs_queue.queue_arn],
            )
        )

        # allow sentinel role to retrieve from s3 bucket
        self.sentinel_role.add_to_policy(
            iam.PolicyStatement(
                actions=["S3:Get*", "S3:List*"],
                resources=[
                    self.sentinel_bucket.bucket_arn,
                    self.sentinel_bucket.arn_for_objects(key_pattern="*")
                ],
            )
        )

        # allow sentinel role to decrypt sqs kms key
        self.sentinel_role.add_to_policy(
            iam.PolicyStatement(
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                resources=[
                    self.sqs_key.key_arn
                ],
            )
        )

        NagSuppressions.add_resource_suppressions(
            self.sentinel_role,
            [
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason="Permission requires wildcard resource",
                )
            ],
            True,
        )

        CfnOutput(
            self,
            "sentinel_bucket_name_output",
            value=self.sentinel_bucket.bucket_name,
            export_name="SentinelBucketName",
        )

        CfnOutput(
            self,
            "sentinel_bucket_arn_output",
            value=self.sentinel_bucket.bucket_arn,
            export_name="SentinelBucketArn",
        )

        CfnOutput(
            self,
            "sentinel_role_arn_output",
            value=self.sentinel_role.role_arn,
            export_name="SentinelRoleArn",
        )

        CfnOutput(
            self,
            "sentinel_queue_url_output",
            value=self.sentinel_sqs_queue.queue_url,
            export_name="SentinelQueueURL",
        )