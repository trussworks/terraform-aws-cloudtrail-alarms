package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/gruntwork-io/terratest/modules/terraform"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"

)

func TestTerraformAwsCloudTrailAlarms(t *testing.T) {
	awsRegion := "us-west-2"

	logs := aws.NewCloudWatchLogsClient(t, awsRegion)
	logGroupNameVar := "test"
	logGroupInput := cloudwatchlogs.CreateLogGroupInput{LogGroupName: &logGroupNameVar}
	logs.CreateLogGroup(&logGroupInput)
	t.Parallel()

	tempTestFolder := test_structure.CopyTerraformFolderToTemp(t, "../", ".")
	alarm_sns_topic_arn := "arn:aws:cloudwatch:us-west-2:123456789012:alarm:myCloudWatchAlarm-CPUAlarm-UXMMZK36R55Z"
	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		
		// The path to where our Terraform code is located
		TerraformDir: tempTestFolder,
		
		// Variables to pass to our Terraform code using -var options
		Vars: map[string]interface{}{
			"alarm_sns_topic_arn": alarm_sns_topic_arn,
			"cloudtrail_log_group_name": "test",
		},

		// Environment variables to set when running Terraform
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

}
