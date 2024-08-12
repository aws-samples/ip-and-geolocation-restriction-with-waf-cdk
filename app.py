# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# # SPDX-License-Identifier: MIT-0

import aws_cdk as cdk
from WAF_Stack import WAF

# Variables
aws_acccount = "AWS_ACCOUNT"
region = "AWS_REGION"
ip_list = ["CIDR_RANGE_1", "CIDR_RANGE_2"]
geo_list = ["COUNTRY_CODE_1", "COUNTRY_CODE_2"]
aws_managed_rules = True

app = cdk.App()

if region == "us-east-1":
    WAF.WAFStack(
        app,
        "waf-stack",
        env=cdk.Environment(account=aws_acccount, region=region),
        ip_list=ip_list,
        geo_list=geo_list,
        aws_managed_rules=aws_managed_rules,
        tags={"Project": "WAF-Deployment"},
    )
else:
    WAF.WAFStack(
        app,
        "waf-stack",
        env=cdk.Environment(account=aws_acccount, region=region),
        ip_list=ip_list,
        geo_list=geo_list,
        aws_managed_rules=aws_managed_rules,
        tags={"Project": "WAF-Deployment"},
    )
    WAF.WAFStack(
        app,
        "waf-stack-cloudfront",
        env=cdk.Environment(account=aws_acccount, region="us-east-1"),
        ip_list=ip_list,
        geo_list=geo_list,
        aws_managed_rules=aws_managed_rules,
        cloudfront_only=True,
        tags={"Project": "WAF-Deployment"},
    )

app.synth()
