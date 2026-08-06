// Package owl24 is the Go SDK for the owl24 observability platform: one
// function call wires up traces, logs, and host metrics, exported to
// owl24's hosted ingest endpoint.
package owl24

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
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

// Hardcoded, not configurable: owl24 is a fully-hosted service with one
// fixed ingest endpoint - unlike the API key (per-customer) or user email,
// there's nothing for a caller to legitimately point this at instead. See
// the equivalent, deliberate choice in owl24-js/owl24-py/owl24-java.
const ingestBaseURL = "https://ingest.owl24.dev"

// Go has no runtime package-version introspection (unlike owl24-py's
// importlib.metadata) and go.mod carries no version field of its own -
// module versions live in git tags, external to the source. So this has to
// be maintained by hand, kept in sync with whatever tag gets pushed for
// each release.
const sdkVersion = "0.1.2"

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

var maskPatterns = struct {
	email, creditCard, phone, bearerToken *regexp.Regexp
}{
	email:       regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	creditCard:  regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`),
	phone:       regexp.MustCompile(`(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
	bearerToken: regexp.MustCompile(`Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
}

func maskSensitiveData(text string) string {
	text = maskPatterns.email.ReplaceAllString(text, "[EMAIL_MASKED]")
	text = maskPatterns.creditCard.ReplaceAllString(text, "[CARD_MASKED]")
	text = maskPatterns.phone.ReplaceAllString(text, "[PHONE_MASKED]")
	text = maskPatterns.bearerToken.ReplaceAllString(text, "[TOKEN_MASKED]")
	return text
}

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
			if attr.Value.Type() == attribute.STRING {
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
// exported to owl24's ingest endpoint. Any failure here degrades to a
// no-op rather than taking the host application down - an observability
// SDK failing to initialize shouldn't be able to crash the app it's
// supposed to be observing.
func Init(apiKey, serviceName string) {
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
		semconv.ServiceVersion("0.1.2"),
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
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Owl24] Init failed: %v\n", err)
		return
	}

	trackedTraceExporter := &statusTrackingSpanExporter{delegate: traceExporter, tracker: tracker}
	tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(&maskingSpanProcessor{wrapped: sdktrace.NewBatchSpanProcessor(trackedTraceExporter)}),
		sdktrace.WithSpanProcessor(&dbMetricsSpanProcessor{}),
	)
	otel.SetTracerProvider(tracerProvider)

	metricExporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(ingestBaseURL+"/v1/metrics"),
		otlpmetrichttp.WithHeaders(headers),
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
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Owl24] Init failed: %v\n", err)
		return
	}

	trackedLogExporter := &statusTrackingLogExporter{delegate: logExporter, tracker: tracker}
	loggerProvider = sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(trackedLogExporter)),
	)
	loggl.SetLoggerProvider(loggerProvider)
	otelLogger = loggerProvider.Logger("console-bridge")

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

	// No synchronous "Active" print here: Init() stays non-blocking. Each
	// signal's working/not-working state (and the "engaged fully/partially
	// engaged/failed to engage" aggregate) is instead reported
	// asynchronously by tracker as each signal's first flush resolves.
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
