package configuration

import(
	"os"
	go_core_observ "github.com/eliezerraj/go-core/observability" 
)

// About get otel env var
func GetOtelEnv() go_core_observ.ConfigOTEL {
	childLogger.Info().Str("func","GetOtelEnv").Send()

	var configOTEL	go_core_observ.ConfigOTEL

	configOTEL.TimeInterval = 1
	configOTEL.TimeAliveIncrementer = 1
	configOTEL.TotalHeapSizeUpperBound = 100
	configOTEL.ThreadsActiveUpperBound = 10
	configOTEL.CpuUsageUpperBound = 100
	configOTEL.SampleAppPorts = []string{}

	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") !=  "" {	
		configOTEL.OtelExportEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}

	return configOTEL
}