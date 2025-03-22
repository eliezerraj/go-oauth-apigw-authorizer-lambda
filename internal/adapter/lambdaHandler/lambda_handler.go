package lambdaHandler

import(
	"context"
	"strings"
	"github.com/rs/zerolog/log"

	"github.com/aws/aws-lambda-go/events"

	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/service"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/model"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/erro"

	go_core_observ "github.com/eliezerraj/go-core/observability"	
)

var childLogger = log.With().Str("component", "go-oauth-apigw-authorizer-lambda").Str("package", "internal.adapter.lambdaHandler").Logger()

var tracerProvider go_core_observ.TracerProvider
var policyData model.PolicyData

type LambdaHandler struct {
	workerService 	*service.WorkerService
	model 			string
}

func InitializeLambdaHandler(workerService *service.WorkerService, model string) *LambdaHandler {
	childLogger.Info().Str("func","InitializeLambdaHandler").Send()

    return &LambdaHandler{
		workerService: workerService,
		model: model,
    }
}

// About lambda handler
func (h *LambdaHandler) LambdaHandlerRequest(ctx context.Context,
											request events.APIGatewayCustomAuthorizerRequestTypeRequest ) (events.APIGatewayCustomAuthorizerResponse, error) {
	childLogger.Info().Str("func","LambdaHandlerRequest").Interface("request", request).Send()

	//trace
	span := tracerProvider.Span(ctx, "adapter.lambdaHandler.LambdaHandlerRequest")
	defer span.End()

	// get the resquest-id and put in inside the 
	ctx = context.WithValue(ctx, "trace-request-id", request.RequestContext.RequestID)

	// Set policy data
	policyData.Effect = "Deny"
	policyData.PrincipalID = "go-oauth-apigw-authorization-lambda"
	policyData.Message = "unauthorized"
	policyData.MethodArn = request.MethodArn

	//token structure
	bearerToken, err := tokenStructureValidation(ctx, request)
	if err != nil{
		switch err {
		case erro.ErrArnMalFormad:
			policyData.Message = "token validation - arn invalid"
		case erro.ErrBearTokenFormad:
			policyData.Message = "token validation - beared token invalid"
		default:
			policyData.Message = "token validation"
		}
		return h.workerService.GeneratePolicyFromClaims(ctx, policyData, nil), nil
	}

	// Load the signature model
	var JwtKeySign	interface{}
	if h.model == "HS256" {
		JwtKeySign = h.workerService.Keys.JwtKey
		h.workerService.TokenSignedValidation = service.TokenValidationHS256
	} else {
		JwtKeySign = h.workerService.Keys.Key_rsa_pub
		h.workerService.TokenSignedValidation = service.TokenValidationRSA
	}

	// Check token signature
	claims, err := h.workerService.TokenSignedValidation(*bearerToken, JwtKeySign)
	if err != nil {
		childLogger.Error().Err(err).Msg("erro TokenSignedValidation")
		return h.workerService.GeneratePolicyFromClaims(ctx, policyData, claims), nil
	}

	//CRL
	/*if(true){
		childLogger.Debug().Interface("ClientCert.ClientCertPem : ", request.RequestContext.Identity.ClientCert.ClientCertPem).Msg("")

		res_crl, err := h.usecaseCerts.VerifyCertCRL(ctx, request.RequestContext.Identity.ClientCert.ClientCertPem)
		if err != nil || !res_crl{
			policyData.Message = "unauthorized cert revoked"
		}
		return h.workerService.GeneratePolicyFromClaims(ctx, policyData), nil
	}*/

	// Scope ON
	if (true) {
		// Check scope
		if !h.workerService.ScopeValidation(ctx, *claims, policyData.MethodArn) {
			policyData.Message = "unauthorized by token validation"
			return h.workerService.GeneratePolicyFromClaims(ctx, policyData, claims), nil
		} 
	}

	policyData.Effect = "Allow"
	policyData.Message = "Authorized"

	return h.workerService.GeneratePolicyFromClaims(ctx, policyData, claims), nil												
}

// About check the token structure
func tokenStructureValidation(ctx context.Context, request events.APIGatewayCustomAuthorizerRequestTypeRequest) (*string, error){
	childLogger.Info().Str("func","tokenStructureValidation").Send()

	span := tracerProvider.Span(ctx, "adapter.lambdaHandler.tokenStructureValidation")
	defer span.End()
	
	//Check the size of arn
	if (len(request.MethodArn) < 6 || request.MethodArn == ""){
		childLogger.Error().Str("request.MethodArn size error : ", string(rune(len(request.MethodArn)))).Msg("")
		return nil, erro.ErrArnMalFormad
	}

	//Parse the method and path
	arn := strings.SplitN(request.MethodArn, "/", 4)
	method := arn[2]
	path := arn[3]

	childLogger.Debug().Interface("method : ", method).Msg("")
	childLogger.Debug().Interface("path : ", path).Msg("")

	//Extract the token from header
	var token string
	if (request.Headers["Authorization"] != "")  {
		token = request.Headers["Authorization"]
	} else if (request.Headers["authorization"] != "") {
		token = request.Headers["authorization"]
	}

	// check format token
	var bearerToken string
	tokenSlice := strings.Split(token, " ")
	if len(tokenSlice) > 1 {
		bearerToken = tokenSlice[len(tokenSlice)-1]
	} else {
		bearerToken = token
	}

	// length
	if len(bearerToken) < 1 {
		childLogger.Error().Msg("empty token")
		return nil, erro.ErrBearTokenFormad
	}

	return &bearerToken, nil
}
