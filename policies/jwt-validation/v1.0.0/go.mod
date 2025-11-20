// JWT validation policy go.mod
module github.com/envoy-policy-engine/policies/jwt-validation

go 1.23.0

require (
	github.com/envoy-policy-engine/sdk v1.0.0
	github.com/golang-jwt/jwt/v5 v5.2.1
)

replace github.com/envoy-policy-engine/sdk => ../../../sdk
