variable "cloudtrail_log_group_name" {
  description = "Cloudwatch log group name for Cloudtrail logs"
  type        = string
  default     = "cloudtrail-events"
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for generated alarms"
  type        = string
}