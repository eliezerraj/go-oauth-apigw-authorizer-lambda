# Define environment variables
export API_VERSION=3.3
export POD_NAME=go-oauth-apigw-authorizer-lambda
export ENV=dev

export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
export USE_STDOUT_TRACER_EXPORTER=false
export USE_OTLP_COLLECTOR=true

export MODEL_SIGN=RSA
export REGION=us-east-2
export SECRET_NAME=key-jwt-auth
export DYNAMO_TABLE_NAME=user_login_2

export RSA_BUCKET_NAME_KEY=docktech-eliezer-908671954593-truststore-mtls
export RSA_FILE_PATH=/
export RSA_PRIV_FILE_KEY=server-private.key
export RSA_PUB_FILE_KEY=server-public.key
export CRL_FILE_KEY=crl-ca.crl
export DEFAULT_API_KEY_USAGE_PLAN_TIER_1=2J8D44g4gTuojQ78pS3L4KTI936KKAx3gFueVTqg
export DEFAULT_API_KEY_USAGE_PLAN_TIER_2=APIKEY-TIER-02-0000-0002
export DEFAULT_API_KEY_USAGE_PLAN_TIER_3=APIKEY-TIER-03-0000-0003

# Default target
all: run

# Show environment variables
env:
	@echo "Current Environment Variables:"
	@echo "API_VERSION=$(API_VERSION)"
	@echo "POD_NAME=$(POD_NAME)"
	@echo "MODEL_SIGN=$(MODEL_SIGN)"

# Run the Go application
run:
	@echo "Running application with environment variables..."
	@go run main.go

# Clean build cache
clean:
	@echo "Cleaning build cache..."
	@go clean

.PHONY: all env run clean