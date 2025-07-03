from dataclasses import dataclass

from aws_cdk import (
    Stack, 
    aws_iam as iam, 
    aws_lambda as _lambda, 
    aws_logs as logs, 
    aws_events as events,
    aws_events_targets as targets,
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
    """Generate the Lambda AWS infrastructure for Sentinel. Lambda function runs every 2 hours to scan CloudWatch logs"""

    def __init__(
        self, scope: Construct, construct_id: str, props: LambdaProps, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create Lambda function for scheduled processing every 2 hours
        self.sentinel_function = _lambda.Function(
            self,
            "sentinel_function",
            code=_lambda.Code.from_asset("./lambda_to_s3/function"),
            handler="sentinel_function.handler",
            runtime=_lambda.Runtime.PYTHON_3_11,
            environment={
                "S3_BUCKET": props.bucket_name,
                "PROCESSING_MODE": "scheduled",
                "SCAN_INTERVAL_HOURS": "2",
                "LOG_GROUP_NAME": props.log_group_name
            },
            log_retention=logs.RetentionDays.TWO_WEEKS,
            timeout=Duration.minutes(10),  # Increased timeout for batch processing
            memory_size=512,  # Increased memory for processing larger batches
            description="Processes CloudTrail logs every 2 hours and forwards filtered events to S3",
            architecture=_lambda.Architecture.X86_64,
        )

        # Grant S3 permissions to Lambda
        self.sentinel_function.add_to_role_policy(
            iam.PolicyStatement(
                sid="S3AllowLambdaPost",
                actions=["s3:PutObject", "s3:ListBucket", "s3:GetBucketAcl"],
                resources=[props.bucket_arn, f"{props.bucket_arn}/*"],
            )
        )

        # Grant CloudWatch Logs permissions for reading log events
        self.sentinel_function.add_to_role_policy(
            iam.PolicyStatement(
                sid="CloudWatchLogsRead",
                actions=[
                    "logs:FilterLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:{props.log_group_name}:*",
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ],
            )
        )

        # Create EventBridge rule to trigger Lambda every 2 hours
        scheduled_rule = events.Rule(
            self,
            "SentinelScheduledRule",
            description="Trigger Sentinel Lambda function every 2 hours to process CloudTrail logs",
            schedule=events.Schedule.rate(Duration.hours(2))  # Every 2 hours
        )

        # Add the Lambda function as a target for the scheduled rule
        scheduled_rule.add_target(
            targets.LambdaFunction(
                self.sentinel_function,
                retry_attempts=2,  # Retry failed executions
            )
        )

        # Import CloudTrail log group for reference (but don't create subscription filter)
        self.cloudtrail_log_group = logs.LogGroup.from_log_group_name(
            self,
            "cloudtrail_log_group",
            log_group_name=props.log_group_name,
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

        # Outputs
        CfnOutput(
            self,
            "SentinelLambdaFunctionArn",
            value=self.sentinel_function.function_arn,
            export_name="SentinelLambdaFunctionArn",
            description="ARN of the Sentinel CloudTrail processing Lambda function"
        )

        CfnOutput(
            self,
            "SentinelScheduleRule",
            value=scheduled_rule.rule_arn,
            export_name="SentinelScheduleRuleArn",
            description="ARN of the EventBridge rule that triggers Lambda every 2 hours"
        )

        CfnOutput(
            self,
            "ProcessingConfiguration",
            value="Mode: Scheduled every 2 hours, Memory: 512MB, Timeout: 10min",
            description="Lambda processing configuration details"
        )