from dataclasses import dataclass

# from typing import Union, Literal
from aws_cdk import (
    Stack, 
    aws_iam as iam, 
    aws_lambda as _lambda, 
    aws_logs as logs, 
    aws_logs_destinations as logs_destinations,
    Duration,
    CfnOutput
)
import aws_cdk as cdk
from cdk_nag import NagSuppressions, NagPackSuppression

from constructs import Construct


@dataclass
class LambdaProps:
    bucket_name: str
    bucket_arn: str
    log_group_name: str


class LambdaStack(Stack):
    """Generate the Lambda AWS infrastructure for Sentinel. Lambda function, execution role and cloudwatch logs group"""

    def __init__(
        self, scope: Construct, construct_id: str, props: LambdaProps, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create Lambda function with Python 3.11 runtime
        self.sentinel_function = _lambda.Function(
            self,
            "sentinel_function",
            code=_lambda.Code.from_asset("./lambda_to_s3/function"),
            handler="sentinel_function.handler",
            runtime=_lambda.Runtime.PYTHON_3_11,  # UPDATED: Changed from PYTHON_3_9 to PYTHON_3_11
            environment={"S3_BUCKET": props.bucket_name},
            log_retention=logs.RetentionDays.TWO_WEEKS,
            timeout=Duration.minutes(5),  # ADDED: Explicit timeout for processing CloudTrail logs
            memory_size=256,  # ADDED: Explicit memory size
            description="Processes CloudTrail logs and forwards filtered events to S3 for Sentinel ingestion",
            architecture=_lambda.Architecture.X86_64,  # ADDED: Explicit architecture
        )

        # Grant S3 permissions to Lambda
        self.sentinel_function.add_to_role_policy(
            iam.PolicyStatement(
                sid="S3AllowLambdaPost",
                actions=["s3:PutObject", "s3:ListBucket", "s3:GetBucketAcl"],
                resources=[props.bucket_arn, f"{props.bucket_arn}/*"],
            )
        )

        # ADDED: CloudWatch Logs permissions for Lambda function
        self.sentinel_function.add_to_role_policy(
            iam.PolicyStatement(
                sid="CloudWatchLogsAccess",
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream", 
                    "logs:PutLogEvents"
                ],
                resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"],
            )
        )

        # Import CloudTrail log group managed by Control Tower
        self.cloudtrail_log_group = logs.LogGroup.from_log_group_name(
            self,
            "cloudtrail_log_group",
            log_group_name=props.log_group_name,
        )

        # Add subscription filter with improved filter pattern
        self.cloudtrail_log_group.add_subscription_filter(
            "lambda_subscription_filter",
            destination=logs_destinations.LambdaDestination(
                fn=self.sentinel_function
            ),
            filter_pattern=logs.FilterPattern.literal(
                '{ $.eventSource = "signin.amazonaws.com" '
                '|| $.eventSource = "sso.amazonaws.com" '
                '|| $.eventSource = "wafv2.amazonaws.com" '
                '|| $.eventSource = "secretsmanager.amazonaws.com" '
                '|| $.eventSource = "guardduty.amazonaws.com" '
                '|| $.eventSource = "route53.amazonaws.com" '
                '|| $.eventSource = "iam.amazonaws.com" }'
            ),
        )

        # Add CDK-Nag suppressions
        NagSuppressions.add_stack_suppressions(
            self,
            [
                NagPackSuppression(
                    id="AwsSolutions-IAM4", reason="Ok to use managed policy for Lambda execution role."
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5", reason="Ok for wildcard permissions in CloudWatch Logs."
                ),
            ],
            True,
        )

        # Add resource-specific suppressions for Lambda function
        NagSuppressions.add_resource_suppressions(
            self.sentinel_function,
            [
                NagPackSuppression(
                    id="AwsSolutions-L1", 
                    reason="Python 3.11 is a supported and current runtime."
                ),
            ],
            True,
        )

        # Output Lambda function ARN for reference
        CfnOutput(
            self,
            "SentinelLambdaFunctionArn",
            value=self.sentinel_function.function_arn,
            export_name="SentinelLambdaFunctionArn",
            description="ARN of the Sentinel CloudTrail processing Lambda function"
        )

        # Output Lambda function name for reference
        CfnOutput(
            self,
            "SentinelLambdaFunctionName",
            value=self.sentinel_function.function_name,
            export_name="SentinelLambdaFunctionName",
            description="Name of the Sentinel CloudTrail processing Lambda function"
        )