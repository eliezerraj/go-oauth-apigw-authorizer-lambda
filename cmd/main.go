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

	"github.com/aws/aws-lambda-go/events"
	//"github.com/aws/aws-lambda-go/lambda"

	go_core_observ "github.com/eliezerraj/go-core/observability"
	go_core_bucket_s3 "github.com/eliezerraj/go-core/aws/bucket_s3"
	go_core_cert "github.com/eliezerraj/go-core/cert"
	go_core_aws_config "github.com/eliezerraj/go-core/aws/aws_config"
	go_core_aws_dynamo "github.com/eliezerraj/go-core/aws/dynamo"
	go_core_aws_secret_manager "github.com/eliezerraj/go-core/aws/secret_manager" 

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/contrib/propagators/aws/xray"
)

var(
	logLevel = 	zerolog.DebugLevel
	appServer	model.AppServer
	awsConfig 	go_core_aws_config.AwsConfig
	databaseDynamo		go_core_aws_dynamo.DatabaseDynamo
	awsSecretManager	go_core_aws_secret_manager.AwsSecretManager
	awsBucketS3			go_core_bucket_s3.AwsBucketS3

	infoTrace go_core_observ.InfoTrace
	tracer 			trace.Tracer
	tracerProvider go_core_observ.TracerProvider
)

// About initialize the enviroment var
func init(){
	log.Debug().Msg("init")
	zerolog.SetGlobalLevel(logLevel)

	infoPod := configuration.GetInfoPod()
	configOTEL 	:= configuration.GetOtelEnv()
	awsService 	:= configuration.GetAwsServiceEnv() 

	appServer.InfoPod = &infoPod
	appServer.ConfigOTEL = &configOTEL
	appServer.AwsService = &awsService

	awsService.BucketNameRSAKey ="eliezerraj-908671954593-mtls-truststore"
	awsService.FilePathRSA="/"
	awsService.FileNameRSAPrivKey="server-private.key"
	awsService.FileNameRSAPubKey="server-public.key"
	awsService.FileNameCrlKey="crl-ca.crl"
	awsService.AwsRegion="us-east-2"
	awsService.SecretName="key-jwt-auth"
}

// About loads all key (HS256 and RSA)
func loadKey(	ctx context.Context, 
				awsService model.AwsService, 
				coreSecretManager 	*go_core_aws_secret_manager.AwsSecretManager,
				coreBucketS3 		*go_core_bucket_s3.AwsBucketS3) (*model.RsaKey, error){
	log.Debug().Msg("loadKey")

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
	log.Debug().Msg("main")
	log.Debug().Msg("----------------------------------------------------")
	log.Debug().Interface("appServer :",appServer).Msg("")
	log.Debug().Msg("----------------------------------------------------")

	ctx := context.Background()

	// otel
	log.Info().Str("OTEL_EXPORTER_OTLP_ENDPOINT :", appServer.ConfigOTEL.OtelExportEndpoint).Msg("")

	infoTrace.PodName = appServer.InfoPod.PodName
	infoTrace.PodVersion = appServer.InfoPod.ApiVersion
	infoTrace.ServiceType = "k8-workload"
	infoTrace.Env = appServer.InfoPod.Env
	infoTrace.AccountID = appServer.InfoPod.AccountID

	tp := tracerProvider.NewTracerProvider(	ctx, 
											appServer.ConfigOTEL, 
											&infoTrace)
	otel.SetTextMapPropagator(xray.Propagator{})
	otel.SetTracerProvider(tp)
	tracer = tp.Tracer(appServer.InfoPod.PodName)

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

	mockEvent := events.APIGatewayCustomAuthorizerRequestTypeRequest{
		Type:       "TOKEN",
		MethodArn:  "arn:aws:execute-api:us-east-2:908671954593:k0ng1bdik7/qa/GET/account/info",
		Headers: map[string]string{
			"Authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJnby1vYXV0aCIsInZlcnNpb24iOiIzIiwiand0X2lkIjoiYWVjMWNkMDgtOGQ2YS00OTMzLThiNTctZjZjZDI5NTA1ODJiIiwidXNlcm5hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIl0sImV4cCI6MTc0MTc1OTk1M30.TY6TSKY1Xr-IdIaN6yEcQFTG6zHXBgxQj8XGcDBu4jLI0bK20cCzmvCEi40sVof52RTc5i5fXSeFqRC17Ua7jdVY-DW9iT17nacjHeJl4d1A3pVGM1bTVRttRe2_klSB7hgvKyesCUKbHbUqJW_7iZY_ld_0BW7Vr6v7sINcZfrg-lWWV2xqI8wIRUAZERA8MzIykVIDkJoM4Ee6YRICDVGXsKCMMxjOhSPIqxV20K6ew-4wgRoeB5SvQiCa2_Oi3TuC1mcm6lqHPHpqyjf6rpIctiE9kfAQXISnO7_5-fe4Ptyrx3KdN4Vyq5w5cSPBL7jHbzk27KKSO3FiyEVFfHKGBfUPCC24xxWDaMJcyw1t_WRyKal4FvWrlsIPsF9lhxrJzOCk1mwNkJ3XWHaWI-6gk_EIOvk0r1syFjeEWGlTTQpiyxl0EI0231shCDlGsDzzNjKDaBdEZ4IK3lGEclPGKk0Ss1TjK3ntRdfQtIq2HCYzq4hGslAf2hzQSYyS7vNwnM6uZojg6k6oaIlGszeRsbwfXaLCPdMBfif6h3K0aEPfv6EMYOae933P3NvcAPCCLREOzeblo7dv-mayQdmOzf7bZfuCDvH_e04TWEcDOGznGnlhOk_DvJCDaa0DNF9iG3EFoA7cye8IGtxHiFci-XejSavscZ2WrAZg7LE",
		},
	}
	mockEvent = events.APIGatewayCustomAuthorizerRequestTypeRequest{
		Type:       "TOKEN",
		MethodArn:  "arn:aws:execute-api:us-east-2:908671954593:k0ng1bdik7/qa/GET/account/info",
		Headers: map[string]string{
			"Authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJnby1vYXV0aCIsInZlcnNpb24iOiIzIiwiand0X2lkIjoiYWVjMWNkMDgtOGQ2YS00OTMzLThiNTctZjZjZDI5NTA1ODJiIiwidXNlcm5hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIl0sImV4cCI6MTc0MTc1OTk1M30.TY6TSKY1Xr-IdIaN6yEcQFTG6zHXBgxQj8XGcDBu4jLI0bK20cCzmvCEi40sVof52RTc5i5fXSeFqRC17Ua7jdVY-DW9iT17nacjHeJl4d1A3pVGM1bTVRttRe2_klSB7hgvKyesCUKbHbUqJW_7iZY_ld_0BW7Vr6v7sINcZfrg-lWWV2xqI8wIRUAZERA8MzIykVIDkJoM4Ee6YRICDVGXsKCMMxjOhSPIqxV20K6ew-4wgRoeB5SvQiCa2_Oi3TuC1mcm6lqHPHpqyjf6rpIctiE9kfAQXISnO7_5-fe4Ptyrx3KdN4Vyq5w5cSPBL7jHbzk27KKSO3FiyEVFfHKGBfUPCC24xxWDaMJcyw1t_WRyKal4FvWrlsIPsF9lhxrJzOCk1mwNkJ3XWHaWI-6gk_EIOvk0r1syFjeEWGlTTQpiyxl0EI0231shCDlGsDzzNjKDaBdEZ4IK3lGEclPGKk0Ss1TjK3ntRdfQtIq2HCYzq4hGslAf2hzQSYyS7vNwnM6uZojg6k6oaIlGszeRsbwfXaLCPdMBfif6h3K0aEPfv6EMYOae933P3NvcAPCCLREOzeblo7dv-mayQdmOzf7bZfuCDvH_e04TWEcDOGznGnlhOk_DvJCDaa0DNF9iG3EFoA7cye8IGtxHiFci-XejSavscZ2WrAZg7LE",
		},
	}

	handler.LambdaHandlerRequest(ctx, mockEvent)
}