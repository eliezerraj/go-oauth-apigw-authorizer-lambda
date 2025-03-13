# go-oauth-apigw-authorizer-lambda

go-oauth-apigw-authorizer-lambda

## Lambda Env Variables

    APP_NAME: go-oauth-apigw-authorizer-lambda
    OTEL_EXPORTER_OTLP_ENDPOINT: localhost:4
    AWS_REGION:us-east-2
    RSA_BUCKET_NAME_KEY:eliezerraj-908671954593-mtls-truststore
    RSA_FILE_PATH:/
    RSA_PRIV_FILE_KEY:private_key.pem
    RSA_PUB_FILE_KEY:public_key.pem
    CRL_FILE_KEY: crl-ca.crl
    SECRET_NAME:key-jwt-auth
    DYNAMO_TABLE_NAME: user_login_2
    VERSION: '3.0'
    MODEL_SIGN: "RSA"

    ## Compile lambda

## Manually compile the function

      New Version
      GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap ./cmd/main.go
      zip main.zip bootstrap

    aws lambda update-function-code \
        --region us-east-2 \
        --function-name go-oauth-apigw-authorizer-lambda \
        --zip-file fileb:///mnt/c/Eliezer/workspace/github.com/go-oauth-apigw-authorizer-lambda/main.zip \
        --publish

+ Test APIGW

        {
        "headers": {
            "authorization": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpc3MiOiJsYW1iZGEtZ28tYXV0ZW50aWNhdGlvbiIsInZlcnNpb24iOiIyIiwiand0X2lkIjoiN2RmZGI4MDctZmU2ZC00NDE2LWE3YTgtZDA3NmRiM2ZlYTc1IiwidXNlcm5hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFkbWluIl0sImV4cCI6MTczMzU0MDE2OX0.BFpRsLG26M_q_edK0RhtoMGibViupmEZJuQv1Nnqa2k"
        },
        "methodArn": "arn:aws:execute-api:us-east-2:908671954593:k0ng1bdik7/qa/GET/account/info"
        }