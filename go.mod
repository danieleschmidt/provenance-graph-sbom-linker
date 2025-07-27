module github.com/your-org/provenance-graph-sbom-linker

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/neo4j/neo4j-go-driver/v5 v5.15.0
	github.com/redis/go-redis/v9 v9.3.0
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.17.0
	github.com/stretchr/testify v1.8.4
	github.com/golang/mock v1.6.0
	github.com/onsi/ginkgo/v2 v2.13.2
	github.com/onsi/gomega v1.30.0
	github.com/sigstore/cosign/v2 v2.2.2
	github.com/anchore/syft v0.98.0
	github.com/CycloneDX/cyclonedx-go v0.7.2
	github.com/spdx/tools-golang v0.5.3
	github.com/prometheus/client_golang v1.17.0
	go.opentelemetry.io/otel v1.21.0
	go.opentelemetry.io/otel/trace v1.21.0
	go.opentelemetry.io/otel/metric v1.21.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.21.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v0.44.0
	go.opentelemetry.io/otel/sdk v1.21.0
	go.opentelemetry.io/otel/sdk/metric v1.21.0
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/google/uuid v1.4.0
	golang.org/x/crypto v0.16.0
	golang.org/x/sync v0.5.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.1
	go.uber.org/zap v1.26.0
	go.uber.org/multierr v1.11.0
	github.com/swaggo/swag v1.16.2
	github.com/swaggo/gin-swagger v1.6.0
	github.com/swaggo/files v1.0.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)