# Dangling DNS Detection

AWS Config custom rule for detecting dangling CNAME records in Amazon Route 53 that could lead to subdomain takeover attacks.

## Introduction

Subdomain takeover occurs when a CNAME record points to an AWS resource that has been deleted, allowing a threat actor to claim the resource name and serve malicious content under your domain. This is a known issue across globally shared AWS namespaces (Amazon S3 buckets, Amazon CloudFront distributions, AWS Elastic Beanstalk environments) and is classified by MITRE ATT&CK under T1584.001 (Compromise Infrastructure - Domains).

This solution helps you detect dangling CNAME records before they can be exploited. It runs as an AWS Config custom rule that:

- Discovers CNAME records across all your Amazon Route 53 hosted zones
- Pattern-matches CNAME targets against known AWS resource hostnames
- Cross-references targets against AWS Config inventory to verify the underlying resource still exists
- Reports NON_COMPLIANT findings to AWS Config and AWS Security Hub
- Optionally publishes notifications to Amazon SNS

This README covers the architecture, deployment, verification, security considerations, cleanup, and related cost considerations for the solution.

## Overview

This solution detects "dangling" CNAME records that point to AWS resources no longer present in the customer's AWS account. Such records could be exploited by attackers to serve malicious content under the customer's domain.

## Supported AWS Resource Types

- Amazon S3 buckets
- Amazon CloudFront distributions
- AWS Elastic Beanstalk environments

## Roadmap

The following resource types are planned but not yet implemented:

- Elastic Load Balancing (Application Load Balancer, Network Load Balancer, Classic Load Balancer)

## Architecture

The solution uses an AWS Config custom rule backed by an AWS Lambda function that:

1. Discovers all CNAME records from Amazon Route 53 hosted zones
2. Matches CNAME targets against known AWS resource patterns
3. Queries AWS Config inventory to check if target resources exist
4. Reports compliance status to AWS Config
5. Creates AWS Security Hub findings for non-compliant records
6. Publishes Amazon SNS notifications for alerting
7. Publishes Amazon CloudWatch metrics for monitoring

## Installation

### Prerequisites

- Python 3.11+
- AWS CLI configured with appropriate credentials
- AWS Config enabled in the target account

### Development Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

### Cost Considerations

This solution creates AWS resources that incur charges, including:

- AWS Lambda function executions, billed per invocation. Frequency depends on the AWS Config evaluation schedule and number of Amazon Route 53 records.
- AWS Config rule evaluations, billed per evaluation.
- Amazon CloudWatch Logs storage and custom metrics.
- AWS Security Hub findings (if Security Hub is enabled in the account).
- Amazon SQS Dead Letter Queue storage for failed Lambda invocations.
- AWS KMS key for encrypting Lambda environment variables and the DLQ, billed monthly plus per API request.

Costs scale with your Amazon Route 53 record count and the AWS Config evaluation frequency you configure (default: every 24 hours). For current rates in your AWS Region, see the [AWS Lambda pricing page](https://aws.amazon.com/lambda/pricing/), the [AWS Config pricing page](https://aws.amazon.com/config/pricing/), and the [AWS pricing calculator](https://calculator.aws/#/). To control ongoing charges, follow the Cleanup section when the solution is no longer needed.

### Deployment

```bash
# Package Lambda function
./scripts/package.sh

# Deploy CloudFormation stack
aws cloudformation deploy \
    --template-file infrastructure/template.yaml \
    --stack-name dangling-dns-detection \
    --capabilities CAPABILITY_IAM
```

### Verification

After the deployment completes, verify that the solution is working:

1. Check that the AWS CloudFormation stack reached `CREATE_COMPLETE`:

   ```bash
   aws cloudformation describe-stacks \
       --stack-name dangling-dns-detection \
       --query "Stacks[0].StackStatus"
   ```

2. Confirm that the AWS Config rule is active:

   ```bash
   aws configservice describe-config-rules \
       --config-rule-names dangling-dns-detection
   ```

3. Trigger an immediate evaluation to confirm the rule runs end-to-end:

   ```bash
   aws configservice start-config-rules-evaluation \
       --config-rule-names dangling-dns-detection
   ```

4. After a few minutes, review evaluation results in the AWS Config console or via the CLI. NON_COMPLIANT findings indicate dangling CNAME records.

## Cleanup

To avoid ongoing charges, delete the CloudFormation stack when you no longer need the solution:

```bash
aws cloudformation delete-stack --stack-name dangling-dns-detection
```

Verify that stack deletion completed:

```bash
aws cloudformation describe-stacks --stack-name dangling-dns-detection
```

You should receive a `Stack with id dangling-dns-detection does not exist` error once deletion is complete.

**Note:** Deleting the stack removes all resources created by the template, including the AWS Lambda function, Lambda permissions, AWS Config rule, Amazon CloudWatch Logs log group, Amazon CloudWatch Dashboard, AWS Key Management Service (AWS KMS) key and alias (with a 30-day deletion window for the key), Amazon Simple Queue Service (Amazon SQS) Dead Letter Queue, and associated AWS Identity and Access Management (AWS IAM) roles and policies. AWS Config rule evaluation history is retained unless manually deleted. AWS Security Hub findings are automatically deleted after 90 days (active findings) or 30 days (archived findings) if not updated. If you need to retain findings or Amazon CloudWatch Logs for audit purposes, export them before the retention period expires or before stack deletion.

## Project Structure

```
├── src/                    # Lambda function source code
│   ├── __init__.py
│   ├── models.py          # Data models and enums
│   ├── pattern_matcher.py # AWS resource pattern matching
│   ├── discovery.py       # Route 53 CNAME discovery
│   ├── inventory.py       # Config inventory queries
│   ├── evaluator.py       # Compliance evaluation logic
│   ├── alerting.py        # Security Hub and SNS integration
│   ├── metrics.py         # CloudWatch metrics publishing
│   └── handler.py         # Lambda handler entry point
├── infrastructure/         # CloudFormation templates
│   └── template.yaml
├── tests/                  # Test suite
│   ├── unit/              # Unit tests
│   └── property/          # Property-based tests
├── scripts/               # Build and deployment scripts
├── pyproject.toml         # Project configuration
└── README.md
```

## Testing

```bash
# Run all tests
pytest

# Run unit tests only
pytest tests/unit/

# Run property-based tests only
pytest tests/property/

# Run with coverage
pytest --cov=src --cov-report=html
```

## Security Considerations

This solution is provided as sample code for educational purposes and as a reference implementation. Before deploying to production:

- Test in a lower environment first (development or staging account) using test hosted zones with non-production DNS records. Validate detection accuracy, IAM permissions, and notification thresholds before promoting to production.
- Review the IAM permissions in the CloudFormation template and scope them to your organization's least-privilege requirements.
- Evaluate the AWS Security Hub finding severity and Amazon SNS notification thresholds for your environment.
- Consider enabling AWS Config Aggregator if you need cross-account visibility.
- This solution does not perform automated remediation (DNS record deletion). Non-compliant findings require manual review before action.

### Accepted IAM exceptions

The CloudFormation template uses `Resource: '*'` in several IAM statements where AWS API design requires it. Each is documented inline in the template and is also tracked here:

- **`route53:ListHostedZones` and `route53:ListResourceRecordSets`** - These actions do not support resource-level permissions. They operate across all hosted zones in the account by design.
- **`config:SelectResourceConfig`** - The AWS Config advanced query action does not support resource-level permissions. The solution uses it to query AWS Config inventory across the account.
- **`cloudwatch:PutMetricData`** - This action does not support resource-level permissions. Access is restricted via the `cloudwatch:namespace` condition key, scoping it to the `DanglingDNS/Detection` namespace only.
- **`sts:GetCallerIdentity`** - This action does not support resource-level permissions. It returns the caller's own identity, so the wildcard is inherently scoped to the caller.
- **AWS KMS key policy** - The `AllowAccountRoot` statement in the AWS KMS key policy uses `Action: 'kms:*'` with `Resource: '*'`. This is the standard AWS-recommended pattern for AWS KMS key policies. The policy is attached to the key itself, the resource is the key, and the statement is scoped by the `Principal` field to the account root only. Restricting the action would prevent the account root from rotating, scheduling deletion, or otherwise managing the key, which would break the recovery escape hatch documented in the AWS KMS developer guide.

These exceptions are also annotated with `cfn_nag` rule suppressions and a Checkov `CKV_AWS_111` skip in the template metadata, with the same justification.

## Conclusion

Subdomain takeover is a preventable misconfiguration that begins with a dangling DNS record. This solution gives you proactive detection across all your Amazon Route 53 hosted zones, integrates findings into AWS Security Hub, and notifies you via Amazon SNS so your team can act before the resource name can be reclaimed. Combine it with the operational practice of always deleting DNS records before the underlying resource, and the new Amazon S3 account regional namespaces feature where applicable, for a layered defense.

To extend the solution, see the Roadmap section above for additional resource types planned for future support. Contributions are welcome through pull requests on the upstream repository.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
