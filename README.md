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

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.13.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 3.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 3.0 |

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
| <a name="input_alarm_namespace"></a> [alarm\_namespace](#input\_alarm\_namespace) | Namespace for generated Cloudwatch alarms | `string` | `"CISBenchmark"` | no |
| <a name="input_alarm_sns_topic_arn"></a> [alarm\_sns\_topic\_arn](#input\_alarm\_sns\_topic\_arn) | SNS topic ARN for generated alarms | `string` | n/a | yes |
| <a name="input_aws_config_changes"></a> [aws\_config\_changes](#input\_aws\_config\_changes) | Toggle AWS Config changes alarm | `bool` | `true` | no |
| <a name="input_cloudtrail_cfg_changes"></a> [cloudtrail\_cfg\_changes](#input\_cloudtrail\_cfg\_changes) | Toggle Cloudtrail config changes alarm | `bool` | `true` | no |
| <a name="input_cloudtrail_log_group_name"></a> [cloudtrail\_log\_group\_name](#input\_cloudtrail\_log\_group\_name) | Cloudwatch log group name for Cloudtrail logs | `string` | `"cloudtrail-events"` | no |
| <a name="input_console_signin_failures"></a> [console\_signin\_failures](#input\_console\_signin\_failures) | Toggle console signin failures alarm | `bool` | `true` | no |
| <a name="input_disable_assumed_role_login_alerts"></a> [disable\_assumed\_role\_login\_alerts](#input\_disable\_assumed\_role\_login\_alerts) | Toggle to disable assumed role console login alerts - violates CIS Benchmark | `bool` | `false` | no |
| <a name="input_disable_or_delete_cmk"></a> [disable\_or\_delete\_cmk](#input\_disable\_or\_delete\_cmk) | Toggle disable or delete CMK alarm | `bool` | `true` | no |
| <a name="input_iam_changes"></a> [iam\_changes](#input\_iam\_changes) | Toggle IAM changes alarm | `bool` | `true` | no |
| <a name="input_nacl_changes"></a> [nacl\_changes](#input\_nacl\_changes) | Toggle network ACL changes alarm | `bool` | `true` | no |
| <a name="input_network_gw_changes"></a> [network\_gw\_changes](#input\_network\_gw\_changes) | Toggle network gateway changes alarm | `bool` | `true` | no |
| <a name="input_no_mfa_console_login"></a> [no\_mfa\_console\_login](#input\_no\_mfa\_console\_login) | Toggle no MFA console login alarm | `bool` | `true` | no |
| <a name="input_root_usage"></a> [root\_usage](#input\_root\_usage) | Toggle root usage alarm | `bool` | `true` | no |
| <a name="input_route_table_changes"></a> [route\_table\_changes](#input\_route\_table\_changes) | Toggle route table changes alarm | `bool` | `true` | no |
| <a name="input_s3_bucket_policy_changes"></a> [s3\_bucket\_policy\_changes](#input\_s3\_bucket\_policy\_changes) | Toggle S3 bucket policy changes alarm | `bool` | `true` | no |
| <a name="input_security_group_changes"></a> [security\_group\_changes](#input\_security\_group\_changes) | Toggle security group changes alarm | `bool` | `true` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags for resources created | `map(string)` | `{}` | no |
| <a name="input_unauthorized_api_calls"></a> [unauthorized\_api\_calls](#input\_unauthorized\_api\_calls) | Toggle unauthorized api calls alarm | `bool` | `true` | no |
| <a name="input_vpc_changes"></a> [vpc\_changes](#input\_vpc\_changes) | Toggle VPC changes alarm | `bool` | `true` | no |

## Outputs

No outputs.
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->

### Testing

[Terratest](https://github.com/gruntwork-io/terratest) is being used for
automated testing with this module. Tests in the `test` folder can be run
locally by running the following command:

```text
make test
```

Or with aws-vault:

```text
AWS_VAULT_KEYCHAIN_NAME=<NAME> aws-vault exec <PROFILE> -- make test
```

