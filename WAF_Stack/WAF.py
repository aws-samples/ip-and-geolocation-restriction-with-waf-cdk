# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# # SPDX-License-Identifier: MIT-0

import aws_cdk as cdk
from aws_cdk import aws_wafv2 as wafv2


class WAFStack(cdk.Stack):
    def __init__(
        self,
        scope: cdk.App,
        construct_id: str,
        ip_list: list,
        geo_list: list,
        cloudfront_only=False,
        aws_managed_rules=False,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        if not cloudfront_only:
            # Generate Regional IP set
            ip_set_regional = wafv2.CfnIPSet(
                self,
                "RegionalIPset",
                name="regional-ipset",
                description="Regional IP addresses allowed",
                addresses=ip_list,
                ip_address_version="IPV4",
                scope="REGIONAL",
            )

            # Generate regional web ACL
            acl = wafv2.CfnWebACL(
                self,
                "Web-ACL-ApiGW",
                default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
                scope="REGIONAL",
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=True,
                    metric_name="waf-apigw",
                    sampled_requests_enabled=True,
                ),
                rules=self.get_waf_rules(ip_set_regional, geo_list, aws_managed_rules),
            )

        if self.region == "us-east-1":
            # Generate global IP set (CloudFront)
            ip_set_cloudfront = wafv2.CfnIPSet(
                self,
                "GlobalIPset",
                name="global-ipset",
                description="global IP addresses allowed",
                addresses=ip_list,
                ip_address_version="IPV4",
                scope="CLOUDFRONT",
            )

            # Generate global web ACL (CloudFront)
            global_acl = wafv2.CfnWebACL(
                self,
                "Web-ACL-Cloudfront",
                default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
                scope="CLOUDFRONT",
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    cloud_watch_metrics_enabled=True,
                    metric_name="waf-cloudfront",
                    sampled_requests_enabled=True,
                ),
                rules=self.get_waf_rules(
                    ip_set_cloudfront, geo_list, aws_managed_rules
                ),
            )

    @staticmethod
    def get_waf_rules(ip_set_regional=None, geo_list=None, aws_managed_rules=False):
        """Generate WAF rules"""
        waf_rules = []
        waf_rules.append(
            wafv2.CfnWebACL.RuleProperty(
                name="IPMatch",
                statement=wafv2.CfnWebACL.StatementProperty(
                    not_statement=wafv2.CfnWebACL.NotStatementProperty(
                        statement=wafv2.CfnWebACL.StatementProperty(
                            ip_set_reference_statement={"arn": ip_set_regional.attr_arn}
                        )
                    )
                ),
                action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name="IPMatch",
                ),
                priority=0,
            )
        )
        waf_rules.append(
            wafv2.CfnWebACL.RuleProperty(
                name="GeoMatch",
                statement=wafv2.CfnWebACL.StatementProperty(
                    not_statement=wafv2.CfnWebACL.NotStatementProperty(
                        statement=wafv2.CfnWebACL.StatementProperty(
                            geo_match_statement=wafv2.CfnWebACL.GeoMatchStatementProperty(
                                country_codes=geo_list
                            )
                        )
                    )
                ),
                action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name="GeoMatch",
                ),
                priority=1,
            )
        )
        if aws_managed_rules:
            waf_rules.append(
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesAdminProtectionRuleSet",
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesAdminProtectionRuleSet",
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWS-AWSManagedRulesAdminProtectionRuleSet",
                    ),
                    priority=2,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                )
            )
            waf_rules.append(
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesAmazonIpReputationList",
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesAmazonIpReputationList",
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWS-AWSManagedRulesAmazonIpReputationList",
                    ),
                    priority=3,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                )
            )
            waf_rules.append(
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesCommonRuleSet",
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS", name="AWSManagedRulesCommonRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWS-AWSManagedRulesCommonRuleSet",
                    ),
                    priority=4,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                )
            )
            waf_rules.append(
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesKnownBadInputsRuleSet",
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesKnownBadInputsRuleSet",
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWS-AWSManagedRulesKnownBadInputsRuleSet",
                    ),
                    priority=5,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                )
            )
            waf_rules.append(
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesLinuxRuleSet",
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS", name="AWSManagedRulesLinuxRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWS-AWSManagedRulesLinuxRuleSet",
                    ),
                    priority=6,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                )
            )
            waf_rules.append(
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesSQLiRuleSet",
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS", name="AWSManagedRulesSQLiRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWS-AWSManagedRulesSQLiRuleSet",
                    ),
                    priority=7,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                )
            )

        return waf_rules
