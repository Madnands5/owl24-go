package owl24

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// dbMetricsSpanProcessor derives DB query metrics (count, duration, errors)
// from spans tagged with the `db.system` OTel semantic-convention attribute
// - the Go equivalent of owl24-js's DbMetricsSpanProcessor. Unlike
// owl24-js/owl24-py, Go has no bytecode-weaving/monkey-patching mechanism to
// auto-tag driver calls with that attribute, so those spans have to come
// from somewhere explicit - see DB below, which callers wrap their *sql.DB
// with to get exactly that. Once a span carries db.system, this processor
// picks it up the same way regardless of who created it.
//
// Instruments are created lazily (guarded by once, not in the constructor)
// since the global MeterProvider isn't registered via otel.SetMeterProvider
// until later in Init() - this processor is attached to the tracer provider
// before that happens, but no real span ends before Init() itself returns.
// Feeds the same metric reader as otelruntime's host metrics, so these ride
// the existing OTLP metrics export pipeline into the same `metrics` table
// dashboard-api.js already reads CPU/memory from - no separate ingestion
// path needed.
type dbMetricsSpanProcessor struct {
	once          sync.Once
	queryCount    otelmetric.Int64Counter
	queryDuration otelmetric.Float64Histogram
	queryErrors   otelmetric.Int64Counter
}

func (p *dbMetricsSpanProcessor) ensureInstruments() {
	p.once.Do(func() {
		meter := otel.Meter("owl24-db-metrics")
		p.queryCount, _ = meter.Int64Counter("db.query.count",
			otelmetric.WithDescription("Number of database queries observed via auto-instrumented spans"))
		p.queryDuration, _ = meter.Float64Histogram("db.query.duration_ms",
			otelmetric.WithDescription("Database query duration in milliseconds"),
			otelmetric.WithUnit("ms"))
		p.queryErrors, _ = meter.Int64Counter("db.query.error_count",
			otelmetric.WithDescription("Number of database queries that ended in an error"))
	})
}

func (p *dbMetricsSpanProcessor) OnStart(ctx context.Context, s sdktrace.ReadWriteSpan) {}

func (p *dbMetricsSpanProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
	var dbSystem, dbName string
	for _, attr := range s.Attributes() {
		switch attr.Key {
		case "db.system":
			dbSystem = attr.Value.AsString()
		case "db.name":
			dbName = attr.Value.AsString()
		}
	}
	if dbSystem == "" {
		return
	}

	p.ensureInstruments()
	if p.queryCount == nil || p.queryDuration == nil || p.queryErrors == nil {
		return
	}

	attrs := []attribute.KeyValue{attribute.String("db.system", dbSystem)}
	if dbName != "" {
		attrs = append(attrs, attribute.String("db.name", dbName))
	}
	opt := otelmetric.WithAttributes(attrs...)

	ctx := context.Background()
	durationMs := float64(s.EndTime().Sub(s.StartTime())) / float64(time.Millisecond)
	p.queryCount.Add(ctx, 1, opt)
	p.queryDuration.Record(ctx, durationMs, opt)
	if s.Status().Code == codes.Error {
		p.queryErrors.Add(ctx, 1, opt)
	}
}

func (p *dbMetricsSpanProcessor) Shutdown(ctx context.Context) error { return nil }

func (p *dbMetricsSpanProcessor) ForceFlush(ctx context.Context) error { return nil }

// DB wraps a *sql.DB and creates a span (tagged with db.system/db.name) around
// every query/exec, which dbMetricsSpanProcessor above then turns into
// db.query.count/db.query.duration_ms/db.query.error_count. This is the
// closest Go equivalent to what getNodeAutoInstrumentations() and the
// psycopg2/pymongo/pymysql/sqlalchemy instrumentors give owl24-js/owl24-py
// for free: since Go has no driver auto-instrumentation, a caller has to
// opt in explicitly by wrapping their *sql.DB with this instead of calling
// its methods directly.
//
//	db, _ := sql.Open("postgres", dsn)
//	tracedDB := owl24.WrapDB(db, "postgresql", "mydb")
//	rows, err := tracedDB.QueryContext(ctx, "SELECT 1")
type DB struct {
	inner    *sql.DB
	dbSystem string
	dbName   string
}

// WrapDB wraps db so its queries/execs are traced and reported as DB
// metrics. dbSystem should be an OTel `db.system` value (e.g. "postgresql",
// "mysql", "sqlite"); dbName is the database name and may be left empty.
func WrapDB(db *sql.DB, dbSystem, dbName string) *DB {
	return &DB{inner: db, dbSystem: dbSystem, dbName: dbName}
}

func (d *DB) startSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	ctx, span := Tracer().Start(ctx, name)
	attrs := []attribute.KeyValue{attribute.String("db.system", d.dbSystem)}
	if d.dbName != "" {
		attrs = append(attrs, attribute.String("db.name", d.dbName))
	}
	span.SetAttributes(attrs...)
	return ctx, span
}

func endSpan(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}

// QueryContext wraps (*sql.DB).QueryContext.
func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	ctx, span := d.startSpan(ctx, "db.query")
	rows, err := d.inner.QueryContext(ctx, query, args...)
	endSpan(span, err)
	return rows, err
}

// QueryRowContext wraps (*sql.DB).QueryRowContext. Errors surface later,
// from the returned *sql.Row's own Scan/Err, so - unlike QueryContext/
// ExecContext - the span here can only ever report as OK.
func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	ctx, span := d.startSpan(ctx, "db.query")
	row := d.inner.QueryRowContext(ctx, query, args...)
	endSpan(span, nil)
	return row
}

// ExecContext wraps (*sql.DB).ExecContext.
func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	ctx, span := d.startSpan(ctx, "db.exec")
	result, err := d.inner.ExecContext(ctx, query, args...)
	endSpan(span, err)
	return result, err
}
