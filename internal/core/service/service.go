package service

import(
	"time"
	"github.com/rs/zerolog/log"

	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/model"	
	go_core_aws_dynamo "github.com/eliezerraj/go-core/aws/dynamo"
)

var childLogger = log.With().Str("component","go-oauht-lambda").Str("package","internal.core.service").Logger()

type WorkerService struct {
	coreDynamoDB 		*go_core_aws_dynamo.DatabaseDynamo
	awsService			*model.AwsService
	Keys				*model.RsaKey
	TokenSignedValidation 	func(string, interface{}) (*model.JwtData, error)
	CreatedToken 			func(interface{}, time.Time, model.JwtData) (*model.Authentication, error)
}

// About create a ner worker service
func NewWorkerService(	coreDynamoDB 		*go_core_aws_dynamo.DatabaseDynamo,
						awsService			*model.AwsService,
						keys				*model.RsaKey,
						tokenSignedValidation 	func(string, interface{}) (*model.JwtData, error),
						createdToken 			func(interface{}, time.Time, model.JwtData) (*model.Authentication, error) ) (*WorkerService, error) {
	childLogger.Info().Str("func","NewWorkerService").Send()

	return &WorkerService{	coreDynamoDB: coreDynamoDB,
							awsService: awsService,
							Keys: keys,
							TokenSignedValidation: tokenSignedValidation,
							CreatedToken: createdToken,
	}, nil
}