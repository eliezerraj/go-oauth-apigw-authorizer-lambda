package service

import (
	"fmt"
	"time"
	"context"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/aws/aws-lambda-go/events"
	"github.com/golang-jwt/jwt/v4"

	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/model"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/erro"
	
	go_core_aws_dynamo "github.com/eliezerraj/go-core/aws/dynamo"
	go_core_observ "github.com/eliezerraj/go-core/observability"
)

var tracerProvider go_core_observ.TracerProvider

var childLogger = log.With().Str("component","go-oauth-apigw-authorizer-lambda").Str("package","internal.core.service").Logger()

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

// About check token HS256 expired/signature and claims
func TokenValidationHS256(bearerToken string, hs256Key interface{}) ( *model.JwtData, error){
	childLogger.Info().Str("func","TokenValidationHS256").Send()

	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(fmt.Sprint(hs256Key)), nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	return claims, nil
}

// About check token RSA expired/signature and claims
func TokenValidationRSA(bearerToken string, rsaPubKey interface{})( *model.JwtData, error){
	childLogger.Info().Str("func","TokenValidationRSA").Send()

	claims := &model.JwtData{}
	tkn, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		return rsaPubKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, erro.ErrStatusUnauthorized
		}
		return nil, erro.ErrTokenExpired
	}

	if !tkn.Valid {
		return nil, erro.ErrStatusUnauthorized
	}

	return claims, nil
}

// About create token HS256
func CreatedTokenHS256(Hs256Key interface{}, expirationTime time.Time, jwtData model.JwtData) (*model.Authentication, error){
	childLogger.Info().Str("func","CreatedTokenHS256").Send()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtData)
	tokenString, err := token.SignedString([]byte(fmt.Sprint(Hs256Key)))
	if err != nil {
		return nil, err
	}

	authentication := model.Authentication{Token: tokenString, 
								ExpirationTime: expirationTime}

	return &authentication ,nil
}

// About create token RSA
func CreatedTokenRSA(keyRsaPriv interface{}, expirationTime time.Time, jwtData model.JwtData) (*model.Authentication, error){
	childLogger.Info().Str("func","CreatedTokenRSA").Send()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtData)
	tokenString, err := token.SignedString(keyRsaPriv)
	if err != nil {
		return nil, err
	}

	authentication := model.Authentication{Token: tokenString, 
								ExpirationTime: expirationTime}

	return &authentication ,nil
}

// About Generate Policy
func(w *WorkerService) GeneratePolicyFromClaims(ctx context.Context, 
												policyData model.PolicyData,
												claims *model.JwtData) (events.APIGatewayCustomAuthorizerResponse){
	childLogger.Info().Str("func","GeneratePolicyFromClaims").Interface("trace-resquest-id", ctx.Value("trace-request-id")).Send()
	
	// trace
	span := tracerProvider.Span(ctx, "service.GeneratePolicyFromClaims")
	defer span.End()

	// Setup the policy
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: policyData.PrincipalID}
	authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
		Version: "2012-10-17",
		Statement: []events.IAMPolicyStatement{
			{
				Action:   []string{"execute-api:Invoke"},
				Effect:   policyData.Effect,
				Resource: []string{policyData.MethodArn},
			},
		},
	}

	// InsertDataAuthorizationContext
	authResponse.Context = make(map[string]interface{})
	authResponse.Context["authMessage"] = policyData.Message
	//authResponse.UsageIdentifierKey = res_userProfile.ApiKey
	if claims != nil {
		authResponse.Context["jwt_id"] = claims.JwtId
	}
	authResponse.Context["tenant_id"] = "NO-TENANT"

	// check insert usage-plan
	if claims.Tier == "tier1" {
		authResponse.UsageIdentifierKey = w.awsService.DefaultApiKeyUsePlan1
	} else if claims.Tier == "tier2" { 
		authResponse.UsageIdentifierKey = w.awsService.DefaultApiKeyUsePlan2
	} else if claims.Tier == "tier3"{
		authResponse.UsageIdentifierKey = w.awsService.DefaultApiKeyUsePlan3
	} else {
		authResponse.UsageIdentifierKey = w.awsService.DefaultApiKeyUsePlan1
	}

	childLogger.Info().Interface("trace-resquest-id", ctx.Value("trace-request-id")).Interface("authResponse", authResponse).Send()

	return authResponse
}

// About insert session data
func(u *WorkerService) ScopeValidation (ctx context.Context, claims model.JwtData, arn string) bool{
	childLogger.Info().Str("func","ScopeValidation").Interface("trace-resquest-id", ctx.Value("trace-request-id")).Send()
	
	// trace
	span := tracerProvider.Span(ctx, "service.ScopeValidation")
	defer span.End()

	// valid the arn
	res_arn := strings.SplitN(arn, "/", 4)
	method := res_arn[2]
	path := res_arn[3]

		// Valid the scope in a naive way
	var pathScope, methodScope string
	for _, scopeListItem := range claims.Scope {
		// Split ex: versiom.read in 2 parts
		scopeSlice := strings.Split(scopeListItem, ".")
		pathScope = scopeSlice[0]
		
		// In this case when just method informed it means the all methods are allowed (ANY)
		// Ex: path (info) or (admin)
		// if lenght is 1, means only the path was given
		if len(scopeSlice) == 1 {
			if pathScope == "admin" {
				childLogger.Debug().Msg("++++++++++ TRUE ADMIN ++++++++++++++++++")
				return true
			}
			// if the path is equal scope, ex: info (informed) is equal info (scope)
			if strings.Contains(path, scopeSlice[0]) {
				childLogger.Debug().Msg("++++++++++ NO ADMIN BUT SCOPE ANY ++++++++++++++++++")
				return true
			}
		// both was given path + method
		} else {
			// In this case it would check the method and the scope(path)
			// Ex: path/scope (version.read)
			childLogger.Debug().Interface("scopeListItem....", scopeListItem).Msg("")

			methodScope = scopeSlice[1]

			if pathScope == path {
				childLogger.Debug().Msg("PASS - Paths equals !!!")
				if method == "ANY" {
					childLogger.Debug().Msg("ALLOWED - method ANY!!!")
					return true
				} else if 	(method == "GET" && methodScope == "read" ) || 
							(method == "POST" && methodScope == "write" ) ||
							(method == "PUT" && methodScope == "write") ||
							(method == "PATCH" && methodScope == "update") ||
							(method == "DELETE" && methodScope == "delete"){
								childLogger.Debug().Msg("ALLOWED - Methods equals !!!")
					return true
				} 
			}
		}
	}

	return false
}