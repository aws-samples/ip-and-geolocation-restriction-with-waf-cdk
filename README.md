# How to deploy AWS Web Application Firewall (WAF) with CDK to restrict access based on IP address and geolocation

[AWS Web Application Firewall](https://aws.amazon.com/waf/) (WAF) is a web application firewall that helps protect your web applications or APIs against common web exploits and bots that may affect availability, compromise security, or consume excessive resources. It gives you control over how traffic reaches your applications by enabling you to create security rules that control bot traffic and block common attack patterns.

You can associate two types of rules to your WAF:

**AWS Managed rules** - AWS offers a pre-configured set of rules to address common issues such as the OWASP top 10 security risks and automated bots

**Custom rules** - You can also create your own managed-rules to customize access to your web applications and APIs. For example, you can restrict traffic based on a specific list of IP addresses, or on a list of countries.

This repository illustrates how you can easily deploy WAF with [AWS Cloud Development Kit](https://aws.amazon.com/cdk/) (CDK), an open-source software development framework to define your cloud application resources with familiar programming languages such as Python.

For prerequisites and instructions for using this AWS Prescriptive Guidance pattern, refer to the article [How to deploy AWS Web Application Firewall (WAF) with CDK to restrict access based on IP address and geolocation](https://apg-library.amazonaws.com/content/6a5f868a-9c70-4e6e-9986-3738c6d80b0e).