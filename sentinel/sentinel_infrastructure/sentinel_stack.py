from dataclasses import dataclass

# from typing import Union, Literal
from aws_cdk import (
    Stack,
    aws_iam,
    aws_sqs,
    aws_kms,
    aws_s3,
    aws_s3_notifications,
    Duration,
)
import aws_cdk as cdk
from cdk_nag import NagSuppressions, NagPackSuppression

from constructs import Construct


@dataclass
class SentinelProps:
    sentinel_worskpace_id: str
    sentinel_account_id: str


class SentinelStack(Stack):
    """Generate the Sentinel AWS infrastructure. S3 Bucket, SQS queue for cloudtrail logs and role with policies for sentinel to assume"""

    def __init__(
        self, scope: Construct, construct_id: str, props: SentinelProps, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # key for queue encryption
        self.sqs_key = aws_kms.Key(
            self,
            "sentinel_queue_key",
            enable_key_rotation=True,
            description="Key used for sentinel sqs queue",
        )

        # dlq for sentinel queue
        self.sentinel_sqs_dlq = aws_sqs.Queue(self, "sentinel_sqs_dlq")
        dead_letter_queue_settings = aws_sqs.DeadLetterQueue(
            max_receive_count=10, queue=self.sentinel_sqs_dlq
        )

        # queue for sentinel to consume
        self.sentinel_sqs_queue = cdk.aws_sqs.Queue(
            self,
            "sentinel_queue",
            receive_message_wait_time=cdk.Duration.seconds(20),
            retention_period=cdk.Duration.days(1),
            encryption=aws_sqs.QueueEncryption.KMS,
            encryption_master_key=self.sqs_key,
            dead_letter_queue=dead_letter_queue_settings,
        )

        # role for sentinel to assume
        self.sentinel_role = cdk.aws_iam.Role(
            self,
            "sentinel_role",
            assumed_by=cdk.aws_iam.AccountPrincipal(props.sentinel_account_id),
            description="Role for sentinel to ingest logs from s3 and check sqs queue for messages",
            external_ids=[props.sentinel_worskpace_id],
            role_name="AWSSentinelRole",
        )

        # allow sentinel queue to send to dlq
        self.sentinel_sqs_dlq.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid="SQS-Sentinel",
                actions=["SQS:SendMessage"],
                principals=[aws_iam.ServicePrincipal("sqs.amazonaws.com")],
                resources=[self.sentinel_sqs_dlq.queue_arn],
                conditions={
                    "ArnLike": {"aws:SourceArn": self.sentinel_sqs_queue.queue_arn}
                },
            )
        )

        # Bucket for S3 access logging. This bucket can't be logged and must be
        # encrypted with S3 encryption, KMS encryption won't work
        self.s3_access_log_bucket = aws_s3.Bucket(
            self,
            "s3_access_logs",
            encryption=aws_s3.BucketEncryption.S3_MANAGED,
            block_public_access=aws_s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            lifecycle_rules=[
                aws_s3.LifecycleRule(enabled=True, expiration=Duration.days(30))
            ],
        )
        self.s3_access_log_bucket.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid="S3ServerAccessLogs",
                actions=["s3:PutObject"],
                principals=[aws_iam.ServicePrincipal("logging.s3.amazonaws.com")],
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
        # Again can't use KMS encryption, only S3 managed.
        self.sentinel_bucket = aws_s3.Bucket(
            self,
            "sentinel_bucket",
            block_public_access=aws_s3.BlockPublicAccess.BLOCK_ALL,
            encryption=aws_s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            server_access_logs_bucket=self.s3_access_log_bucket,
            versioned=True,
            object_ownership=aws_s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            lifecycle_rules=[
                aws_s3.LifecycleRule(enabled=True, expiration=Duration.days(365))
            ],
        )
        # object created event notification for sqs queue
        self.sentinel_bucket.add_object_created_notification(
            aws_s3_notifications.SqsDestination(self.sentinel_sqs_queue)
        )
        # allow services to access bucket
        self.sentinel_bucket.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid="S3AllowServices",
                actions=["s3:GetBucketAcl", "s3:ListBucket", "s3:PutObject"],
                principals=[
                    aws_iam.ServicePrincipal("logging.s3.amazonaws.com"),
                    aws_iam.ServicePrincipal("lambda.amazonaws.com"),
                    aws_iam.ServicePrincipal("events.amazonaws.com"),
                    aws_iam.ServicePrincipal("config.amazonaws.com"),
                    aws_iam.ServicePrincipal("logs.amazonaws.com"),
                    aws_iam.ArnPrincipal("arn:aws:iam::433833021409:root"),
                    aws_iam.ArnPrincipal("arn:aws:iam::447644794224:root"),
                    aws_iam.ArnPrincipal("arn:aws:iam::541899610442:root"),
                    aws_iam.ArnPrincipal("arn:aws:iam::951237805213:root"),
                    aws_iam.ArnPrincipal("arn:aws:iam::664860481080:root"),
                    aws_iam.ArnPrincipal("arn:aws:iam::764858818887:root"),
                ],
                resources=[
                    self.sentinel_bucket.bucket_arn,
                    self.sentinel_bucket.arn_for_objects(key_pattern="*"),
                ],
            )
        )
        # allow sentinel role to retrieve from bucket
        self.sentinel_bucket.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid="S3AllowSentinelRole",
                actions=["s3:GetObject"],
                principals=[aws_iam.ArnPrincipal(self.sentinel_role.role_arn)],
                resources=[self.sentinel_bucket.arn_for_objects(key_pattern="*")],
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
            aws_iam.PolicyStatement(
                sid="SQS-S3-Notifications",
                actions=["SQS:SendMessage"],
                principals=[aws_iam.ServicePrincipal("s3.amazonaws.com")],
                resources=[self.sentinel_sqs_queue.queue_arn],
                conditions={
                    "ArnLike": {"aws:SourceArn": self.sentinel_bucket.bucket_arn}
                },
            )
        )

        # allow sentinel to consume from queue
        self.sentinel_sqs_queue.add_to_resource_policy(
            aws_iam.PolicyStatement(
                sid="SQS-Sentinel-Receive",
                actions=[
                    "SQS:ChangeMessageVisibility",
                    "SQS:DeleteMessage",
                    "SQS:ReceiveMessage",
                    "SQS:GetQueueUrl",
                ],
                principals=[aws_iam.ArnPrincipal(self.sentinel_role.role_arn)],
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
            aws_iam.PolicyStatement(
                sid="Sentinel-Decrypt",
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                principals=[
                    aws_iam.ArnPrincipal(self.sentinel_role.role_arn),
                    aws_iam.ServicePrincipal("s3.amazonaws.com"),
                ],
                resources=["*"],
            )
        )

        # allow sentinel role to consume from queue
        self.sentinel_role.add_to_policy(
            aws_iam.PolicyStatement(
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
            aws_iam.PolicyStatement(
                actions=["S3:Get*", "S3:List*"],
                resources=[self.sentinel_bucket.bucket_arn],
            )
        )

        # allow sentinel role to decrypt sqs kms key
        self.sentinel_role.add_to_policy(
            aws_iam.PolicyStatement(
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                resources=[
                    self.sqs_key.key_arn
                ],  # , props.management_account_kms_key_arn],
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

        cdk.CfnOutput(
            self,
            "sentinel_bucket_name_output",
            value=self.sentinel_bucket.bucket_name,
            export_name="SentinelBucketName",
        )

        cdk.CfnOutput(
            self,
            "sentinel_bucket_arn_output",
            value=self.sentinel_bucket.bucket_arn,
            export_name="SentinelBucketArn",
        )
