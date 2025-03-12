package service

import (
	"fmt"
	"time"
	"context"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/golang-jwt/jwt/v4"

	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/model"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/erro"

	go_core_observ "github.com/eliezerraj/go-core/observability"
)

var tracerProvider go_core_observ.TracerProvider

// About check token HS256 expired/signature and claims
func TokenValidationHS256(bearerToken string, hs256Key interface{}) ( *model.JwtData, error){
	childLogger.Debug().Msg("TokenValidationHS256")

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
	childLogger.Debug().Msg("TokenValidationRSA")

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
	childLogger.Debug().Msg("CreatedTokenHS256")

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
	childLogger.Debug().Msg("CreatedTokenRSA")

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
	childLogger.Debug().Msg("GeneratePolicyFromClaims")
	
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

	childLogger.Debug().Interface("authResponse : ", authResponse).Msg("")

	return authResponse
}

// About insert session data
func(u *WorkerService) ScopeValidation (ctx context.Context, claims model.JwtData, arn string) bool{
	childLogger.Debug().Msg("ScopeValidation")
	
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