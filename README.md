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
| terraform | ~> 0.13.0 |
| aws | ~> 3.0 |

## Providers

| Name | Version |
|------|---------|
| aws | ~> 3.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| alarm\_namespace | Namespace for generated Cloudwatch alarms | `string` | `"CISBenchmark"` | no |
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
| unauthorized\_api\_calls | Toggle unauthorized api calls alarm | `bool` | `true` | no |
| vpc\_changes | Toggle VPC changes alarm | `bool` | `true` | no |

## Outputs

No output.

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
