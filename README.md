# terraform-aws-cloudtrail-alarms

This module creates a number of Cloudwatch alarms that alert on Cloudtrail
events; they are meant to provide compliance with the AWS CIS benchmark.

This module uses Cloudtrail logs which have been written to a Cloudwatch
logs group; this means for organizations with an organization Cloudtrail,
you only need to put this in the master account.

The following alarms are available in this module; all can be toggled on
or off, but by default all alarms are active.

- AWS Config changes
- Cloudtrail config changes
- Console signin failures
- Disabling or deleting CMK
- IAM changes
- Network ACL changes
- Network gateway changes
- No MFA console logins
- Root account usage
- Route table changes
- S3 bucket policy changes
- Security group changes
- Unauthorized API calls
- VPC changes

These alarms were adapted from those in
<https://github.com/nozaq/terraform-aws-secure-baseline>.

## Usage

```hcl
module "cloudtrail_alarms" {
  source         = "trussworks/cloudtrail-alarms/aws"
  version        = "~> 1.0.0"

  alarm_sns_topic_arn = aws_sns_topic.my_alerts.arn
}
```

## Terraform Versions

Terraform 0.13. Pin module version to `~> 2.X`. Submit pull-requests to `master` branch.

Terraform 0.12. Pin module version to `~> 1.X`. Submit pull-requests to `terraform012` branch.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.13.0 |
| aws | >= 3.0 |

## Providers

| Name | Version |
|------|---------|
| aws | >= 3.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_metric_filter.aws_config_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.cloudtrail_cfg_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.console_signin_failures](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.disable_or_delete_cmk](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.iam_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.nacl_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.network_gw_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.no_mfa_console_signin_assumed_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.no_mfa_console_signin_no_assumed_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.root_usage](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.route_table_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.security_group_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.unauthorized_api_calls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.vpc_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_metric_alarm.aws_config_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.cloudtrail_cfg_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.console_signin_failures](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.disable_or_delete_cmk](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.iam_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.nacl_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.network_gw_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.no_mfa_console_signin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.root_usage](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.route_table_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.s3_bucket_policy_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.security_group_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.unauthorized_api_calls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.vpc_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| alarm\_namespace | Namespace for generated Cloudwatch alarms | `string` | `"CISBenchmark"` | no |
| alarm\_prefix | Prefix for the alarm name | `string` | `""` | no |
| alarm\_sns\_topic\_arn | SNS topic ARN for generated alarms | `string` | n/a | yes |
| aws\_config\_changes | Toggle AWS Config changes alarm | `bool` | `true` | no |
| cloudtrail\_cfg\_changes | Toggle Cloudtrail config changes alarm | `bool` | `true` | no |
| cloudtrail\_log\_group\_name | Cloudwatch log group name for Cloudtrail logs | `string` | `"cloudtrail-events"` | no |
| console\_signin\_failures | Toggle console signin failures alarm | `bool` | `true` | no |
| disable\_assumed\_role\_login\_alerts | Toggle to disable assumed role console login alerts - violates CIS Benchmark | `bool` | `false` | no |
| disable\_or\_delete\_cmk | Toggle disable or delete CMK alarm | `bool` | `true` | no |
| iam\_changes | Toggle IAM changes alarm | `bool` | `true` | no |
| nacl\_changes | Toggle network ACL changes alarm | `bool` | `true` | no |
| network\_gw\_changes | Toggle network gateway changes alarm | `bool` | `true` | no |
| no\_mfa\_console\_login | Toggle no MFA console login alarm | `bool` | `true` | no |
| root\_usage | Toggle root usage alarm | `bool` | `true` | no |
| route\_table\_changes | Toggle route table changes alarm | `bool` | `true` | no |
| s3\_bucket\_policy\_changes | Toggle S3 bucket policy changes alarm | `bool` | `true` | no |
| security\_group\_changes | Toggle security group changes alarm | `bool` | `true` | no |
| tags | Tags for resources created | `map(string)` | `{}` | no |
| unauthorized\_api\_calls | Toggle unauthorized api calls alarm | `bool` | `true` | no |
| vpc\_changes | Toggle VPC changes alarm | `bool` | `true` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->
