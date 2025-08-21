package main

import(
	"context"
	"encoding/json"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/go-oauth-apigw-authorizer-lambda/internal/infra/configuration"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/model"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/service"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/adapter/lambdaHandler"

	//"github.com/aws/aws-lambda-go/events" // use it for a mock local

	go_core_observ "github.com/eliezerraj/go-core/observability"
	go_core_bucket_s3 "github.com/eliezerraj/go-core/aws/bucket_s3"
	go_core_cert "github.com/eliezerraj/go-core/cert"
	go_core_aws_config "github.com/eliezerraj/go-core/aws/aws_config"
	go_core_aws_dynamo "github.com/eliezerraj/go-core/aws/dynamo"
	go_core_aws_secret_manager "github.com/eliezerraj/go-core/aws/secret_manager" 

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/contrib/propagators/aws/xray"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"

	"github.com/aws/aws-lambda-go/lambda" // use it for PRD
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda" // use it for PRD
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-lambda-go/otellambda/xrayconfig" //  use it for PRD
)

var(
	logLevel = 	zerolog.InfoLevel // zerolog.InfoLevel zerolog.DebugLevel

	appServer	model.AppServer
	awsConfig 	go_core_aws_config.AwsConfig
	databaseDynamo		go_core_aws_dynamo.DatabaseDynamo
	awsSecretManager	go_core_aws_secret_manager.AwsSecretManager
	awsBucketS3			go_core_bucket_s3.AwsBucketS3

	infoTrace go_core_observ.InfoTrace
	tracer 			trace.Tracer
	tracerProvider go_core_observ.TracerProvider

	childLogger = log.With().Str("component","go-oauth-apigw-authorizer-lambda").Str("package", "main").Logger()
)

// About initialize the enviroment var
func init(){
	childLogger.Info().Str("func","init").Send()

	zerolog.SetGlobalLevel(logLevel)

	infoPod := configuration.GetInfoPod()
	configOTEL 	:= configuration.GetOtelEnv()
	awsService 	:= configuration.GetAwsServiceEnv() 

	appServer.InfoPod = &infoPod
	appServer.ConfigOTEL = &configOTEL
	appServer.AwsService = &awsService
}

// About loads all key (HS256 and RSA)
func loadKey(	ctx context.Context, 
				awsService model.AwsService, 
				coreSecretManager 	*go_core_aws_secret_manager.AwsSecretManager,
				coreBucketS3 		*go_core_bucket_s3.AwsBucketS3) (*model.RsaKey, error){
	childLogger.Info().Str("func","loadKey").Send()

	//trace
	span := tracerProvider.Span(ctx, "main.loadKey")
	defer span.End()

	// Load symetric key from secret manager
	var certCore go_core_cert.CertCore

	keys := model.RsaKey{}
	secret, err := coreSecretManager.GetSecret(ctx, awsService.SecretName)
	if err != nil {
		return nil, err
	}

	var secretData map[string]string
	if err := json.Unmarshal([]byte(*secret), &secretData); err != nil {
		return nil, err
	}
	keys.JwtKey = secretData["JWT_KEY"]

	// Load the private key
	private_key, err := coreBucketS3.GetObject(ctx, 
												awsService.BucketNameRSAKey,
												awsService.FilePathRSA,
												awsService.FileNameRSAPrivKey )
	if err != nil{
		return nil, err
	}
	// Convert private key
	key_rsa_priv, err := certCore.ParsePemToRSAPriv(private_key)
	if err != nil{
		return nil, err
	}
	keys.Key_rsa_priv = key_rsa_priv

	// Load the private key
	public_key, err := coreBucketS3.GetObject(ctx, 
												awsService.BucketNameRSAKey,
												awsService.FilePathRSA,
												awsService.FileNameRSAPubKey )
	if err != nil{
		return nil, err
	}
	key_rsa_pub, err := certCore.ParsePemToRSAPub(public_key)
	if err != nil{
		return nil, err
	}
	keys.Key_rsa_pub = key_rsa_pub

	// Load the crl
	crl_pem, err := coreBucketS3.GetObject(ctx, 
											awsService.BucketNameRSAKey,
											awsService.FilePathRSA,
											awsService.FileNameCrlKey )
	if err != nil{
		return nil, err
	}
	keys.Crl_pem = *crl_pem

	return &keys, nil
}

// About main
func main (){
	childLogger.Info().Str("func","main").Interface("appServer :",appServer).Send()

	ctx := context.Background()

	// otel
	infoTrace.PodName = appServer.InfoPod.PodName
	infoTrace.PodVersion = appServer.InfoPod.ApiVersion
	infoTrace.ServiceType = "lambda"
	infoTrace.Env = appServer.InfoPod.Env

	tp := tracerProvider.NewTracerProvider(	ctx, 
											appServer.ConfigOTEL, 
											&infoTrace)
	
	if tp != nil {
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(xray.Propagator{})
		tracer = tp.Tracer(appServer.InfoPod.PodName)
	}

	// Start the root tracer
	ctx, span := tracer.Start(ctx, "lambda-main-span")
	defer span.End()

	defer func(ctx context.Context) {
			err := tp.Shutdown(ctx)
			if err != nil {
				log.Error().Err(err).Msg("error shutting down tracer provider")
			}
	}(ctx)

	// Prepare aws services
	awsConfig, err := awsConfig.NewAWSConfig(ctx, appServer.AwsService.AwsRegion)
	if err != nil {
		panic("error create new aws session " + err.Error())
	}

	// Otel over aws services
	otelaws.AppendMiddlewares(&awsConfig.APIOptions)

	// Prepare AWS services
	coreDynamoDB := databaseDynamo.NewDatabaseDynamo(awsConfig)
	coreSecretManager := awsSecretManager.NewAwsSecretManager(awsConfig)
	coreBucketS3 := awsBucketS3.NewAwsS3Bucket(awsConfig)

	// Load all keys
	appServer.RsaKey, err = loadKey(ctx, 
									*appServer.AwsService, 
									coreSecretManager, 
									coreBucketS3)
	if err != nil {
		panic("error get keys" + err.Error())
	}

	// wire	
	workerService, err := service.NewWorkerService(	coreDynamoDB, 
													appServer.AwsService, 
													appServer.RsaKey,
													service.TokenValidationRSA,
													service.CreatedTokenRSA)
	if err != nil {
		panic("error create a workerservice " + err.Error())
	}

	handler := lambdaHandler.InitializeLambdaHandler(workerService, appServer.InfoPod.ModelSign)

	/*mockEvent := events.APIGatewayCustomAuthorizerRequestTypeRequest{
		Type:       "TOKEN",
		MethodArn:  "arn:aws:execute-api:us-east-2:908671954593:k0ng1bdik7/qa/GET/account/info",
		Headers: map[string]string{
			"Authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJnby1vYXV0aCIsInZlcnNpb24iOiIzIiwiand0X2lkIjoiYWVjMWNkMDgtOGQ2YS00OTMzLThiNTctZjZjZDI5NTA1ODJiIiwidXNlcm5hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIl0sImV4cCI6MTc0MTc1OTk1M30.TY6TSKY1Xr-IdIaN6yEcQFTG6zHXBgxQj8XGcDBu4jLI0bK20cCzmvCEi40sVof52RTc5i5fXSeFqRC17Ua7jdVY-DW9iT17nacjHeJl4d1A3pVGM1bTVRttRe2_klSB7hgvKyesCUKbHbUqJW_7iZY_ld_0BW7Vr6v7sINcZfrg-lWWV2xqI8wIRUAZERA8MzIykVIDkJoM4Ee6YRICDVGXsKCMMxjOhSPIqxV20K6ew-4wgRoeB5SvQiCa2_Oi3TuC1mcm6lqHPHpqyjf6rpIctiE9kfAQXISnO7_5-fe4Ptyrx3KdN4Vyq5w5cSPBL7jHbzk27KKSO3FiyEVFfHKGBfUPCC24xxWDaMJcyw1t_WRyKal4FvWrlsIPsF9lhxrJzOCk1mwNkJ3XWHaWI-6gk_EIOvk0r1syFjeEWGlTTQpiyxl0EI0231shCDlGsDzzNjKDaBdEZ4IK3lGEclPGKk0Ss1TjK3ntRdfQtIq2HCYzq4hGslAf2hzQSYyS7vNwnM6uZojg6k6oaIlGszeRsbwfXaLCPdMBfif6h3K0aEPfv6EMYOae933P3NvcAPCCLREOzeblo7dv-mayQdmOzf7bZfuCDvH_e04TWEcDOGznGnlhOk_DvJCDaa0DNF9iG3EFoA7cye8IGtxHiFci-XejSavscZ2WrAZg7LE",
		},
	}*/
	/*mockEvent := events.APIGatewayCustomAuthorizerRequestTypeRequest{
		Type:       "TOKEN",
		MethodArn:  "arn:aws:execute-api:us-east-2:908671954593:k0ng1bdik7/qa/GET/account/info",
		RequestContext: events.APIGatewayCustomAuthorizerRequestTypeRequestContext{
			RequestID: "request-id-12345",
		},
		Headers: map[string]string{
			"Authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJnby1vYXV0aC1sYW1iZGEiLCJ2ZXJzaW9uIjoiMi4xIiwiand0X2lkIjoiMmY4ZWRmNzEtZWM0Yy00MTkyLTgwYjMtNDMwN2Y0MTRkMzczIiwidXNlcm5hbWUiOiJ1c2VyLTAxIiwidGllciI6IiIsImFwaV9hY2Nlc3Nfa2V5IjoiQVBJX0FDQ0VTU19LRVlfVVNFUl8wMSIsInNjb3BlIjpbInRlc3QucmVhZCIsInRlc3Qud3JpdGUiLCJhZG1pbiJdLCJleHAiOjE3NTU5ODk2ODF9.dxw--TAAz_fSnJlqEprB3X1SjzRiKV9QS9vkMcUZfVRUHo7q5CXJtFSoooc13bMC1Cxf7O8B3JJ0gP3PeD5YM69WFvMyKkju_66YSvcJrM0e9YSPNEPM7804BxRH8i7gfcKlxZ0RTfglBSWrDv0KJKnSdFQizJVNlOkQgDUlK4FaJ32syLTOOsGv_uaZ3uWTurZFzPunmWL0Pc-UxyKNDCNARWS_d7UYeM3NjLZ_Z6pGMngKMTiP2iasB-tGlAjBUdOpqdafFWpdRsiM0YXH4pS40Me30r_vmual9ddaV5-HEw62PbGcpcp1UUsLnUZoaMTMyaL7WdwlhmsticrV95sUxw5s5yVsh96Tdz-hiV0neyuHIoIJfFezazAbWLkszNPyiF4hySBB1QlEP90rNX5wOV8EQOuWWjMk8hzH_SCqtCawBu23RqZzrnWTcLddjWdYRNQmkBwGkFhoswNXobPMMPBjRWFCSvWKo1mSvcvGQ991BzNg0kPaA1MdyDO7wfiVgKFSzqZRatxC0hB_eIzO6hTTPg9DFvsKw5Pli6BkF1wdLArVyekMdM4Nyo-Kt-8v9j6ZctoMEku8LADqV820K_5SfbALM5j7hXHeCj0_PQyu0RJQiExOA5cFXjEtywHZk7JdS6Y6jNWkBkK_SN43T5UaaQrXzR5XYE1v1bU",
		},
	}*/

	//handler.LambdaHandlerRequest(ctx, mockEvent)

	lambda.Start(otellambda.InstrumentHandler(handler.LambdaHandlerRequest, xrayconfig.WithRecommendedOptions(tp)... ))
}