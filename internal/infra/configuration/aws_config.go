package configuration

import(
	"os"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/model"
)

// About get AWS service env ver
func GetAwsServiceEnv() model.AwsService {
	childLogger.Debug().Msg("GetAwsServiceEnv")

	var awsService	model.AwsService

	if os.Getenv("AWS_REGION") !=  "" {
		awsService.AwsRegion = os.Getenv("AWS_REGION")
	}

	if os.Getenv("SECRET_NAME") !=  "" {
		awsService.SecretName = os.Getenv("SECRET_NAME")
	}

	if os.Getenv("DYNAMO_TABLE_NAME") !=  "" {
		awsService.DynamoTableName = os.Getenv("DYNAMO_TABLE_NAME")
	}

	return awsService
}