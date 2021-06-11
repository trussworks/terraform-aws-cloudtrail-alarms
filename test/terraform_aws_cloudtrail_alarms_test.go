package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/gruntwork-io/terratest/modules/random"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"

)

func TestTerraformAwsCloudTrailAlarms(t *testing.T) {
	awsRegion := "us-west-2"

	t.Parallel()

	tempTestFolder := test_structure.CopyTerraformFolderToTemp(t, "../", "examples/simple")
	testName := fmt.Sprintf("terratest-aws-cloutrail-alarms-%s", strings.ToLower(random.UniqueId()))
	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{

		// The path to where our Terraform code is located
		TerraformDir: tempTestFolder,

		// Variables to pass to our Terraform code using -var options
		Vars: map[string]interface{}{
			"sns_topic_name": testName,
			"log_group_name": testName,
		},

		// Environment variables to set when running Terraform
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	})

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

}
