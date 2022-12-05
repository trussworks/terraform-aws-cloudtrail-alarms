resource "aws_cloudwatch_log_group" "test" {
  name = var.log_group_name
}

#sns topic
resource "aws_sns_topic" "my_alerts" {
  name = var.sns_topic_name
}

module "cloudtrail_alarms" {
  source                    = "../../"
  alarm_sns_topic_arn       = aws_sns_topic.my_alerts.arn
  cloudtrail_log_group_name = aws_cloudwatch_log_group.test.name
}
