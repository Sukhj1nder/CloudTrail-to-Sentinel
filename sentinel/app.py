#!/usr/bin/env python3
import aws_cdk as cdk
from dacite import from_dict
from cdk_nag import AwsSolutionsChecks

from sentinel_infrastructure.sentinel_stack import SentinelStack, SentinelProps


app = cdk.App()

region = app.node.try_get_context("region")
account = app.node.try_get_context("account-id")
config = app.node.try_get_context("sentinel")

sentinel_props = from_dict(data_class=SentinelProps, data=config)

env = cdk.Environment(account=account, region=region)

SentinelStack(app, "MOJSentinelStack", sentinel_props, env=env)

cdk.Aspects.of(app).add(AwsSolutionsChecks())
app.synth()
