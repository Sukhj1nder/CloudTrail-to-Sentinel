from dataclasses import dataclass

# from typing import Union, Literal
from aws_cdk import Stack, aws_iam, aws_lambda, aws_logs, aws_logs_destinations
import aws_cdk as cdk
from cdk_nag import NagSuppressions, NagPackSuppression

from constructs import Construct


@dataclass
class LambdaProps:
    bucket_name: str
    bucket_arn: str


class LambdaStack(Stack):
    """Generate the Lambda AWS infrastructure for Sentinel. Lambda function, execution role annd cloudwatch logs group"""

    def __init__(
        self, scope: Construct, construct_id: str, props: LambdaProps, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.sentinel_function = aws_lambda.Function(
            self,
            "sentinel_function",
            code=aws_lambda.Code.from_asset("./lambda_to_s3/function"),
            handler="sentinel_function.handler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            environment={"S3_BUCKET": props.bucket_name},
            log_retention=aws_logs.RetentionDays.TWO_WEEKS,
        )

        self.sentinel_function.add_to_role_policy(
            aws_iam.PolicyStatement(
                sid="S3AllowLambdaPost",
                actions=["s3:PutObject", "s3:ListBucket", "s3:GetBucketAcl"],
                resources=[props.bucket_arn, f"{props.bucket_arn}/*"],
            )
        )

        # import cloudtrail log group managed by control tower
        self.cloudtrail_log_group = aws_logs.LogGroup.from_log_group_name(
            self,
            "cloudtrail_log_group",
            log_group_name="aws-controltower/CloudTrailLogs",
        )

        self.cloudtrail_log_group.add_subscription_filter(
            "lambda_subscription_filter",
            destination=aws_logs_destinations.LambdaDestination(
                fn=self.sentinel_function
            ),
            filter_pattern=aws_logs.FilterPattern.literal(
                "{ $.eventSource = "
                "signin.amazonaws.com"
                " || $.eventSource = "
                "sso.amazonaws.com"
                " || $.eventSource = "
                "wafv2.amazonaws.com"
                " || $.eventSource = "
                "secretsmanager.amazonaws.com"
                " || $.eventSource = "
                "guardduty.amazonaws.com"
                " || $.eventSource = "
                "route53.amazonaws.com"
                " || $.eventSource = "
                "iam.amazonaws.com"
                " }"
            ),
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
