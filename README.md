# owl24-go

Go SDK for [owl24](https://owl24.dev) — one function call to send logs, traces, and host metrics to your owl24 dashboard, built on OpenTelemetry. Errors are deduplicated and can be handed straight to your own coding agent, which claims them, writes a fix, and opens a PR.

## Install

```bash
go get github.com/Madnands5/owl24-go
```

## Usage

```go
package main

import (
	"os"

	"github.com/Madnands5/owl24-go"
)

func main() {
	owl24.Init(os.Getenv("OWL24_API_KEY"), "my-service-name")
	defer owl24.Recover()

	// ... your app
}
```

That's it — `owl24.Init(...)` wires up traces, logs, and host metrics pointed at your owl24 ingest endpoint, and bridges Go's standard `log` package so `log.Println(...)`, `log.Printf(...)`, etc. are automatically sent to your dashboard.

## What it does

- **Logs**: bridges Go's standard `log` package (its shared/default logger) — every `log.Print`/`Printf`/`Println` call anywhere in the process is forwarded as a structured log.
- **Traces**: sets up an OpenTelemetry `TracerProvider` exporting via OTLP/HTTP. Use `owl24.Tracer()` to create manual spans — see [Automatic HTTP tracing](#automatic-http-tracing) below for framework auto-instrumentation.
- **Database metrics**: queries run through `owl24.WrapDB(...)` (see [Database metrics](#database-metrics)) are automatically turned into `db.query.count`/`db.query.duration_ms`/`db.query.error_count` on your dashboard's Database page.
- **Host metrics**: CPU, memory, GC, and goroutine counts are collected and exported automatically via `go.opentelemetry.io/contrib/instrumentation/runtime` — no setup required.
- **Crash capture**: `owl24.Recover()` — see below, this is the one place Go's design differs meaningfully from the other owl24 SDKs.
- **PII masking**: emails, credit-card-shaped numbers, phone numbers, and bearer tokens are scrubbed from span attributes and log bodies before they ever leave your process.

## Logging

All log lines are plain text, no icons: `[Owl24] ...`.

Each of the three signals (traces/metrics/logs) reports whether it's actually getting data through, for the life of the process:

- `[Owl24] traces working` / `[Owl24] metrics working` / `[Owl24] logs working` — printed the first time a signal is confirmed delivering (and again after recovering from an outage).
- `[Owl24] traces not working because: <reason>` (same for metrics/logs) — printed once a signal fails 3 consecutive attempts. This only triggers at two points: the very first export attempt for a signal, or the first failure after a signal was previously working — not on every routine flush, so a signal that's already known to be down doesn't spam this line on every scheduled export.
- `[Owl24] engaged fully` / `[Owl24] partially engaged` / `[Owl24] failed to engage` — an aggregate line, re-printed only when it changes, once all three signals have resolved at least once.

This status tracking is entirely local — nothing is reported back to owl24's backend, it's just clearer logging in your own process/console.

## Crash capture — `owl24.Recover()`

Go has no global uncaught-panic hook the way Python's `sys.excepthook`, Node's `process.on('uncaughtException')`, or Java's `Thread.setDefaultUncaughtExceptionHandler` provide. A panic can only ever be recovered by a deferred call in the *exact same goroutine* where it happened — there's no single place to install a process-wide handler. That means you need to explicitly add `defer owl24.Recover()` to `main()` **and to every goroutine you spawn that could panic**:

```go
func main() {
	owl24.Init(apiKey, "my-service")
	defer owl24.Recover()
	// ...
}

go func() {
	defer owl24.Recover()
	// ... work that could panic
}()
```

`Recover()` captures the panic as a FATAL log event, flushes telemetry, then re-panics — the program still crashes exactly as it would have without this, just with a record of it sent to your dashboard first.

Note: an HTTP handler that panics is usually a different story — `net/http`'s own server already recovers panicking handlers per-request internally, so one bad request doesn't take the whole process down (verified: the process stays up, other routes keep working, the client just gets a reset connection). `owl24.Recover()` is for panics *outside* that per-request safety net — background goroutines, workers, `main()` itself.

## Automatic HTTP tracing

`net/http` has no built-in auto-instrumentation the way Flask/Express do. For automatic per-request spans, add [`go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp`](https://pkg.go.dev/go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp) yourself and wrap your handler/mux with `otelhttp.NewHandler(...)` — `owl24.Init()` already sets the global `TracerProvider` that `otelhttp` picks up automatically. For manual spans instead, use `owl24.Tracer()`:

```go
ctx, span := owl24.Tracer().Start(r.Context(), r.URL.Path)
defer span.End()
```

## Database metrics

Go has no driver auto-instrumentation mechanism (no bytecode weaving/monkey-patching), so DB calls need an explicit wrapper to produce traced spans. Wrap your `*sql.DB` with `owl24.WrapDB(...)` and use the returned `*owl24.DB` in place of it:

```go
db, err := sql.Open("postgres", dsn)
tracedDB := owl24.WrapDB(db, "postgresql", "mydb") // dbSystem, dbName

rows, err := tracedDB.QueryContext(ctx, "SELECT 1")
result, err := tracedDB.ExecContext(ctx, "UPDATE ...")
row := tracedDB.QueryRowContext(ctx, "SELECT ...")
```

Each call creates a span tagged with `db.system`/`db.name`, which is automatically turned into `db.query.count`, `db.query.duration_ms`, and `db.query.error_count` on your dashboard's Database page, grouped by DB system.

## Working with your coding agent

Errors ingested via this SDK can be deduplicated and handed straight to your own coding agent - claim, investigate, fix, PR. Reach that queue interactively from Claude Code or Cursor with [owl24-mcp](https://github.com/Madnands5/owl24-mcp), or unattended via REST + AGENTS.md (see the [docs](https://owl24.dev/docs#agent-integration)).

## License

MIT — see [LICENSE](https://github.com/Madnands5/owl24-go/blob/main/LICENSE).
