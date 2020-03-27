# Setup Variables

variable "alarm_namespace" {
  description = "Namespace for generated Cloudwatch alarms"
  type        = string
  default     = "CISBenchmark"
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for generated alarms"
  type        = string
}

variable "cloudtrail_log_group_name" {
  description = "Cloudwatch log group name for Cloudtrail logs"
  type        = string
  default     = "cloudtrail-events"
}

# Alarm Toggles

variable "aws_config_changes" {
  description = "Toggle AWS Config changes alarm"
  type        = bool
  default     = true
}

variable "cloudtrail_cfg_changes" {
  description = "Toggle Cloudtrail config changes alarm"
  type        = bool
  default     = true
}

variable "console_signin_failures" {
  description = "Toggle console signin failures alarm"
  type        = bool
  default     = true
}

variable "disable_or_delete_cmk" {
  description = "Toggle disable or delete CMK alarm"
  type        = bool
  default     = true
}

variable "iam_changes" {
  description = "Toggle IAM changes alarm"
  type        = bool
  default     = true
}

variable "nacl_changes" {
  description = "Toggle network ACL changes alarm"
  type        = bool
  default     = true
}

variable "network_gw_changes" {
  description = "Toggle network gateway changes alarm"
  type        = bool
  default     = true
}

variable "no_mfa_console_login" {
  description = "Toggle no MFA console login alarm"
  type        = bool
  default     = true
}

variable "root_usage" {
  description = "Toggle root usage alarm"
  type        = bool
  default     = true
}

variable "route_table_changes" {
  description = "Toggle route table changes alarm"
  type        = bool
  default     = true
}

variable "s3_bucket_policy_changes" {
  description = "Toggle S3 bucket policy changes alarm"
  type        = bool
  default     = true
}

variable "security_group_changes" {
  description = "Toggle security group changes alarm"
  type        = bool
  default     = true
}

variable "unauthorized_api_calls" {
  description = "Toggle unauthorized api calls alarm"
  type        = bool
  default     = true
}

variable "vpc_changes" {
  description = "Toggle VPC changes alarm"
  type        = bool
  default     = true
}
