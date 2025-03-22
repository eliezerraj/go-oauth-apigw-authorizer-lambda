package configuration

import(
	"os"
	"github.com/rs/zerolog/log"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/model"
)

var childLogger = log.With().Str("component","go-oauth-apigw-authorizer-lambda").Str("package","internal.infra.configuration").Logger()

// About get pod information env var
func GetInfoPod() (	model.InfoPod) {
	childLogger.Info().Str("func","GetInfoPod").Send()

	var infoPod 	model.InfoPod

	if os.Getenv("API_VERSION") !=  "" {
		infoPod.ApiVersion = os.Getenv("API_VERSION")
	}
	if os.Getenv("POD_NAME") !=  "" {
		infoPod.PodName = os.Getenv("POD_NAME")
	}
	if os.Getenv("ENV") !=  "" {	
		infoPod.Env = os.Getenv("ENV")
	}
	if os.Getenv("MODEL_SIGN") !=  "" {	
		infoPod.ModelSign = os.Getenv("MODEL_SIGN")
	}
	return infoPod
}
