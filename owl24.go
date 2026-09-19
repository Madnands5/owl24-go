// Package owl24 is the Go SDK for the owl24 observability platform: one
// function call wires up traces, logs, and host metrics, exported to
// owl24's hosted ingest endpoint. Errors are deduplicated on arrival and
// can be queued straight to your own coding agent, which claims them,
// writes a fix, and opens a PR.
package owl24

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	otelruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	loggl "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.28.0"
	"go.opentelemetry.io/otel/trace"
)

// defaultIngestBaseURL is owl24's hosted ingest endpoint - the default for
// every existing customer. Self-hosted customers (running their own
// collector on their own infrastructure) can override it via
// InitWithConfig's Config.IngestBaseURL. See the equivalent override in
// owl24-js/owl24-py/owl24-java.
const defaultIngestBaseURL = "https://ingest.owl24.dev"

// Config holds optional overrides for InitWithConfig. The zero value
// reproduces today's Init(apiKey, serviceName) behavior exactly, so
// existing hosted customers see zero behavior change.
type Config struct {
	// IngestBaseURL overrides the ingest endpoint. Defaults to
	// defaultIngestBaseURL when empty. Set this to point the SDK at a
	// self-hosted collector instead of owl24's hosted endpoint.
	IngestBaseURL string
}

// Go has no runtime package-version introspection (unlike owl24-py's
// importlib.metadata) and go.mod carries no version field of its own -
// module versions live in git tags, external to the source. So this has to
// be maintained by hand, kept in sync with whatever tag gets pushed for
// each release.
const sdkVersion = "0.1.4"

// checkSdkVersion is called once at the very start of Init() - separate
// from the OTLP exporters below, since their interfaces never expose the
// underlying HTTP response, only success/failure, so there's no way to
// detect ingestor.js's 426 Upgrade Required from inside a normal export
// call. A short timeout and a blanket error-swallow mean a slow/unreachable
// server here degrades to "assume fine, proceed" rather than delaying or
// breaking the host app's own startup.
func checkSdkVersion(ctx context.Context, baseURL, apiKey, userEmail string, timeout time.Duration) bool {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/v1/sdk-check", nil)
	if err != nil {
		return false
	}
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("x-user-email", userEmail)
	req.Header.Set("x-sdk-language", "go")
	req.Header.Set("x-sdk-version", sdkVersion)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var body struct {
		UpdateRequired bool `json:"update_required"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false
	}
	if body.UpdateRequired {
		fmt.Fprintln(os.Stderr, "[Owl24] Please Update package. telemetry shutting down")
		return true
	}
	return false
}

var (
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *metric.MeterProvider
	loggerProvider *sdklog.LoggerProvider
	otelLogger     otellog.Logger
)

// eventIngestConfig, set once at the end of Init(), is what TrackEvent below
// reads - Task H (competitive-roadmap.md).
type eventIngestConfigT struct {
	headers       map[string]string
	serviceName   string
	ingestBaseURL string
}

var eventIngestConfig *eventIngestConfigT

// Task 8 (todolist.md), expanded 2026-08-23 - see masking.go for the full
// detection categories (PCI-DSS cards with Luhn validation, gitleaks-derived
// secret prefixes, IBAN/MOD-97, US routing numbers, IP truncation, RFC1918
// detection, internal hostname suffixes) and the customer-configurable
// field-name mechanism (IsSensitiveFieldName/ConfigureMasking) that backs
// proprietary/business-sensitive data, which has no pattern of its own.
// maskSensitiveData itself now lives in masking.go.

// maskingSpanProcessor wraps another SpanProcessor and masks string
// attributes in OnEnd before they reach the real processor/exporter - the
// Go equivalent of owl24-py's MaskingSpanProcessor. Go's SDK types OnEnd's
// parameter as the read-only ReadOnlySpan interface (and that interface is
// deliberately sealed against external implementations via a private()
// method, unlike Java's SpanData - so owl24-java's "wrap it in a masked
// read-only copy" approach doesn't work here). What does work: the
// concrete type underneath (recordingSpan) also implements the mutable
// ReadWriteSpan interface, so a type assertion recovers write access to
// the very same span, letting us mutate attributes in place instead.
type maskingSpanProcessor struct {
	wrapped sdktrace.SpanProcessor
}

func (p *maskingSpanProcessor) OnStart(parent context.Context, s sdktrace.ReadWriteSpan) {
	p.wrapped.OnStart(parent, s)
}

func (p *maskingSpanProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
	if rw, ok := s.(sdktrace.ReadWriteSpan); ok {
		for _, attr := range s.Attributes() {
			if IsSensitiveFieldName(string(attr.Key)) {
				rw.SetAttributes(attribute.String(string(attr.Key), "[FIELD_MASKED]"))
			} else if attr.Value.Type() == attribute.STRING {
				rw.SetAttributes(attribute.String(string(attr.Key), maskSensitiveData(attr.Value.AsString())))
			}
		}
	}
	p.wrapped.OnEnd(s)
}

func (p *maskingSpanProcessor) Shutdown(ctx context.Context) error {
	return p.wrapped.Shutdown(ctx)
}

func (p *maskingSpanProcessor) ForceFlush(ctx context.Context) error {
	return p.wrapped.ForceFlush(ctx)
}

// consoleBridgeWriter forwards everything written through Go's standard
// `log` package (its shared/default logger - i.e. log.Print/Printf/Println
// anywhere in the process) to both the original destination (so console
// output looks exactly like it always did) and to owl24 as a structured
// log event - the Go equivalent of owl24-py's logging.Handler bridge and
// owl24-js's console.log override.
//
// This does NOT create the export-failure feedback loop that had to be
// guarded against in owl24-py: the OTel Go SDK's own internal
// error-reporting (a failed export, etc.) uses its own independent
// *log.Logger instance that writes straight to os.Stderr - it's created
// once with log.New(os.Stderr, ...) and never touches the shared/default
// logger this bridge patches via log.SetOutput, so there's no risk of an
// export error's own log message being captured and re-exported.
type consoleBridgeWriter struct {
	original *os.File
}

func (w *consoleBridgeWriter) Write(p []byte) (int, error) {
	n, err := w.original.Write(p)
	if otelLogger != nil {
		var rec otellog.Record
		rec.SetTimestamp(time.Now())
		rec.SetBody(otellog.StringValue(maskSensitiveData(string(p))))
		rec.SetSeverity(otellog.SeverityInfo)
		rec.SetSeverityText("INFO")
		rec.AddAttributes(otellog.String("is_winston", "false"))
		otelLogger.Emit(context.Background(), rec)
	}
	return n, err
}

// Init wires up traces, logs, and host metrics for the calling process,
// exported to owl24's hosted ingest endpoint. Any failure here degrades to
// a no-op rather than taking the host application down - an observability
// SDK failing to initialize shouldn't be able to crash the app it's
// supposed to be observing. Equivalent to InitWithConfig(apiKey,
// serviceName, Config{}).
func Init(apiKey, serviceName string) {
	InitWithConfig(apiKey, serviceName, Config{})
}

// InitWithConfig is Init with an optional Config override - most notably
// Config.IngestBaseURL, for self-hosted customers pointing this SDK at
// their own collector instead of owl24's hosted ingest endpoint. A zero
// Config behaves identically to Init.
func InitWithConfig(apiKey, serviceName string, config Config) {
	if apiKey == "" {
		apiKey = os.Getenv("owl24_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("OBSERVE_API_KEY")
	}
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "[Owl24] API Key required.")
		return
	}

	userEmail := os.Getenv("owl24_USER_EMAIL")
	if userEmail == "" {
		userEmail = os.Getenv("OBSERVE_USER_EMAIL")
	}
	if userEmail == "" {
		userEmail = "unknown@local.dev"
	}

	if serviceName == "" {
		serviceName = "dice-server"
	}

	ingestBaseURL := config.IngestBaseURL
	if ingestBaseURL == "" {
		ingestBaseURL = defaultIngestBaseURL
	}

	ctx := context.Background()

	// Server-side version gate (ingestor.js) refuses actual telemetry
	// ingestion from a version this far behind anyway - checking here
	// first means a customer running a known-bad old release finds out via
	// a clear log line at startup, instead of every export silently
	// failing with no explanation.
	if checkSdkVersion(ctx, ingestBaseURL, apiKey, userEmail, 5*time.Second) {
		return
	}

	headers := map[string]string{
		"x-api-key":      apiKey,
		"x-user-email":   userEmail,
		"x-sdk-language": "go",
		"x-sdk-version":  sdkVersion,
	}

	res, err := resource.New(ctx, resource.WithAttributes(
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion("0.1.3"),
	))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Owl24] Init failed: %v\n", err)
		return
	}

	// Tracks whether each of traces/metrics/logs is actually getting
	// through (not just whether it was built without error) - logs
	// "<signal> working"/"<signal> not working because: ..." on each
	// transition and the "engaged fully/partially/failed to engage"
	// aggregate once all 3 have resolved at least once.
	tracker := newStatusTracker()

	traceExporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(ingestBaseURL+"/v1/traces"),
		otlptracehttp.WithHeaders(headers),
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Owl24] Init failed: %v\n", err)
		return
	}

	trackedTraceExporter := &statusTrackingSpanExporter{delegate: traceExporter, tracker: tracker}
	tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(&maskingSpanProcessor{wrapped: sdktrace.NewBatchSpanProcessor(
			trackedTraceExporter,
			// Tuned faster than stock OTel defaults (30s/512/2048) to match
			// this SDK's JS/Python/Java siblings - a deliberate low-latency
			// compromise for an incident-response product, not an oversight.
			sdktrace.WithBatchTimeout(10*time.Second),
			sdktrace.WithMaxExportBatchSize(2048),
			sdktrace.WithMaxQueueSize(8192),
		)}),
		sdktrace.WithSpanProcessor(&dbMetricsSpanProcessor{}),
	)
	otel.SetTracerProvider(tracerProvider)

	metricExporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(ingestBaseURL+"/v1/metrics"),
		otlpmetrichttp.WithHeaders(headers),
		otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Owl24] Init failed: %v\n", err)
		return
	}

	trackedMetricExporter := &statusTrackingMetricExporter{delegate: metricExporter, tracker: tracker}
	meterProvider = metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(trackedMetricExporter, metric.WithInterval(3*time.Second))),
	)
	otel.SetMeterProvider(meterProvider)

	logExporter, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpointURL(ingestBaseURL+"/v1/logs"),
		otlploghttp.WithHeaders(headers),
		otlploghttp.WithCompression(otlploghttp.GzipCompression),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Owl24] Init failed: %v\n", err)
		return
	}

	trackedLogExporter := &statusTrackingLogExporter{delegate: logExporter, tracker: tracker}
	loggerProvider = sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(
			trackedLogExporter,
			// Matches the trace batch processor's tuning above.
			sdklog.WithExportInterval(10*time.Second),
			sdklog.WithExportMaxBatchSize(2048),
			sdklog.WithMaxQueueSize(8192),
		)),
	)
	loggl.SetLoggerProvider(loggerProvider)
	otelLogger = loggerProvider.Logger("console-bridge")

	// Startup jitter: both providers are constructed and registered above,
	// so spans/logs are already being captured from t=0 - this goroutine
	// only staggers the *first flush*, not readiness. Without it, a fleet
	// of processes that all restart at the same wall-clock moment (a
	// rolling deploy, a cold-start burst) would all hit their first
	// BatchTimeout simultaneously and export in lockstep, spiking the
	// ingestor. Deliberately non-blocking (no sleep before Init() returns)
	// so this never delays k8s readiness probes or serverless cold starts.
	go func(tp *sdktrace.TracerProvider, lp *sdklog.LoggerProvider) {
		time.Sleep(time.Duration(rand.Int63n(int64(10 * time.Second))))

		traceFlushCtx, traceCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer traceCancel()
		if err := tp.ForceFlush(traceFlushCtx); err != nil {
			fmt.Fprintf(os.Stderr, "[Owl24] Startup jitter trace flush failed: %v\n", err)
		}

		logFlushCtx, logCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer logCancel()
		if err := lp.ForceFlush(logFlushCtx); err != nil {
			fmt.Fprintf(os.Stderr, "[Owl24] Startup jitter log flush failed: %v\n", err)
		}
	}(tracerProvider, loggerProvider)

	// Host metrics (CPU/GC/memory/goroutines) - the Go equivalent of
	// owl24-js's HostMetrics and owl24-java's runtime-telemetry-java8
	// observers.
	if err := otelruntime.Start(otelruntime.WithMeterProvider(meterProvider)); err != nil {
		fmt.Fprintf(os.Stderr, "[Owl24] Failed to start host metrics: %v\n", err)
	}

	// Bridges Go's standard `log` package (its shared/default logger) to
	// owl24 - the equivalent of owl24-py's logging patch / owl24-js's
	// console.log override. Anything written via log.Print/Printf/Println
	// anywhere in the process (including the standard library's own
	// internal use of it) is forwarded, masked, alongside going to its
	// original destination unchanged.
	log.SetOutput(&consoleBridgeWriter{original: os.Stderr})

	// Task H (competitive-roadmap.md) - TrackEvent() reads this once Init()
	// has resolved the same headers/serviceName every other exporter above
	// already uses.
	eventIngestConfig = &eventIngestConfigT{headers: headers, serviceName: serviceName, ingestBaseURL: ingestBaseURL}

	// No synchronous "Active" print here: Init() stays non-blocking. Each
	// signal's working/not-working state (and the "engaged fully/partially
	// engaged/failed to engage" aggregate) is instead reported
	// asynchronously by tracker as each signal's first flush resolves.
}

// TrackEvent marks a discrete event (a deploy, a feature-flag flip, a
// customer-defined business event) so it shows up as a marker on the
// dashboard's time-series charts - Task H (competitive-roadmap.md).
// Fire-and-forget via a goroutine (matching owl24-js's non-awaited fetch) so
// a slow/unreachable ingest endpoint never blocks the caller. attributes
// values are masked the same way span/log attributes are before they ever
// leave this process - only string-typed values go through the
// value-pattern pass (matching maskingSpanProcessor's own restriction),
// but every key still goes through the field-NAME check regardless of its
// value's type. attributes may be nil.
func TrackEvent(name string, attributes map[string]interface{}) {
	config := eventIngestConfig
	if config == nil {
		fmt.Fprintln(os.Stderr, "[Owl24] TrackEvent() called before Init().")
		return
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "[Owl24] TrackEvent() requires a non-empty name.")
		return
	}

	masked := make(map[string]interface{}, len(attributes))
	for key, value := range attributes {
		if IsSensitiveFieldName(key) {
			masked[key] = "[FIELD_MASKED]"
		} else if s, ok := value.(string); ok {
			masked[key] = maskSensitiveData(s)
		} else {
			masked[key] = value
		}
	}

	go func() {
		body, err := json.Marshal(map[string]interface{}{
			"name":        name,
			"serviceName": config.serviceName,
			"attributes":  masked,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Owl24] TrackEvent() failed: %v\n", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.ingestBaseURL+"/v1/events", bytes.NewReader(body))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Owl24] TrackEvent() failed: %v\n", err)
			return
		}
		for key, value := range config.headers {
			req.Header.Set(key, value)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Owl24] TrackEvent() failed: %v\n", err)
			return
		}
		defer resp.Body.Close()
	}()
}

// Tracer returns a tracer for creating manual spans. Go's net/http has no
// built-in auto-instrumentation the way Flask/Express do - see
// go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp for
// per-handler middleware you can add yourself for that - so tracing HTTP
// handlers needs an explicit span, the same situation owl24-java's
// getTracer() documents for the JDK's built-in HttpServer. Returns a
// global no-op tracer if called before Init(), rather than a nil/panic,
// consistent with the rest of this SDK degrading to a no-op instead of
// taking the host app down.
func Tracer() trace.Tracer {
	if tracerProvider == nil {
		return otel.Tracer("owl24-go")
	}
	return tracerProvider.Tracer("owl24-go")
}

// Recover captures a panic as a FATAL log event and flushes telemetry
// before re-panicking. Go has no global uncaught-panic hook the way
// Python's sys.excepthook, Node's process.on('uncaughtException'), or
// Java's Thread.setDefaultUncaughtExceptionHandler provide - a panic can
// only ever be recovered by a deferred call in the exact same goroutine
// where it happened, so there's no single place to install a process-wide
// handler. Callers need to explicitly add this to every goroutine that
// could panic, most importantly main():
//
//	func main() {
//	    owl24.Init(apiKey, "my-service")
//	    defer owl24.Recover()
//	    ...
//	}
//
// Re-panics after capturing so the program still crashes/exits exactly as
// it would have without this - Recover only adds telemetry, it doesn't
// change Go's normal panic/crash behavior.
func Recover() {
	if r := recover(); r != nil {
		message := fmt.Sprintf("[panic] %v\n%s", r, string(debug.Stack()))
		if otelLogger != nil {
			var rec otellog.Record
			rec.SetTimestamp(time.Now())
			rec.SetBody(otellog.StringValue(maskSensitiveData(message)))
			rec.SetSeverity(otellog.SeverityFatal)
			rec.SetSeverityText("FATAL")
			rec.AddAttributes(otellog.String("error.type", "panic"))
			otelLogger.Emit(context.Background(), rec)
		}
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if loggerProvider != nil {
			_ = loggerProvider.ForceFlush(flushCtx)
		}
		if tracerProvider != nil {
			_ = tracerProvider.ForceFlush(flushCtx)
		}
		fmt.Fprintf(os.Stderr, "[Owl24] Recovered panic: %v\n", r)
		panic(r)
	}
}

// Shutdown flushes and stops all telemetry providers.
func Shutdown() {
	fmt.Println("Shutting down telemetry...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if tracerProvider != nil {
		_ = tracerProvider.Shutdown(ctx)
	}
	if loggerProvider != nil {
		_ = loggerProvider.Shutdown(ctx)
	}
	if meterProvider != nil {
		_ = meterProvider.Shutdown(ctx)
	}
}
