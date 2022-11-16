#!/usr/bin/env python3
import aws_cdk as cdk
from dacite import from_dict
from cdk_nag import AwsSolutionsChecks

from lambda_to_s3.lambda_stack import LambdaStack, LambdaProps


app = cdk.App()

region = app.node.try_get_context("region")
bucket_name = app.node.try_get_context("bucket_name")
bucket_arn = app.node.try_get_context("bucket_arn")
bucket_context: dict = {"bucket_name": bucket_name, "bucket_arn": bucket_arn}

stage = app.node.try_get_context("stage")
context: dict = app.node.try_get_context(stage)
env = cdk.Environment(account=context["account-id"], region=region)

# lambda_props = from_dict(data_class=LambdaProps, data=config)
# env = cdk.Environment(account=account, region=region)

lambda_stack = LambdaStack(
    app,
    "MOJLambdaStack",
    env=env,
    props=from_dict(data_class=LambdaProps, data=bucket_context),
)

cdk.Aspects.of(app).add(AwsSolutionsChecks())
app.synth()
