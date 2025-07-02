#!/usr/bin/env python3
import aws_cdk as cdk
from dacite import from_dict
from cdk_nag import AwsSolutionsChecks

from lambda_to_s3.lambda_stack import LambdaStack, LambdaProps


app = cdk.App()

region = app.node.try_get_context("region")
bucket_name = app.node.try_get_context("bucket_name")
bucket_arn = app.node.try_get_context("bucket_arn")
log_group_name = app.node.try_get_context("log_group_name")
bucket_context: dict = {
    "bucket_name": bucket_name, 
    "bucket_arn": bucket_arn, 
    "log_group_name": log_group_name
}

stage = app.node.try_get_context("stage")
context: dict = app.node.try_get_context(stage)

# Validate required context
if not context or "account-id" not in context:
    raise ValueError(f"Missing account-id in context for stage: {stage}")

if not region:
    raise ValueError("Missing region in context")

env = cdk.Environment(account=context["account-id"], region=region)

# Validate bucket context
if not bucket_name or not bucket_arn or not log_group_name:
    raise ValueError("Missing required bucket configuration in context")

lambda_stack = LambdaStack(
    app,
    "LambdaStack",
    env=env,
    props=from_dict(data_class=LambdaProps, data=bucket_context),
)

# Add CDK-Nag security checks
cdk.Aspects.of(app).add(AwsSolutionsChecks())
app.synth()