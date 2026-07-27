package owl24

import (
	"context"
	"fmt"
	"sync"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Tracks working/not-working status per signal ("traces"/"metrics"/"logs")
// and confirms state transitions with a bounded retry before declaring a
// pipeline down, instead of reacting to a single failed flush - collector
// hiccups are common and shouldn't cause a false "not working" the moment a
// scheduled export overlaps a blip.
//
// Retries only fire at the two points that matter: the very first export
// attempt for a signal ("initiating"), and the first failure after a signal
// was previously confirmed working ("stopped working midway") - NOT on
// every routine flush while a signal is in a known-good or known-bad steady
// state. The underlying OTLP exporters already retry/bound themselves
// internally up to their own configured timeout (see
// github.com/cenkalti/backoff/v5, pulled in transitively for exactly this);
// wrapping every flush in another round of retries could make one flush
// take far longer than the scheduled export interval and pile up during a
// real outage.

type signalState int

const (
	statePending signalState = iota
	stateWorking
	stateNotWorking
)

const maxAttempts = 3

var backoffDelays = [maxAttempts - 1]time.Duration{300 * time.Millisecond, 800 * time.Millisecond}

// statusTracker is shared by the three per-signal exporter wrappers below.
// Exports for different signals happen on different goroutines/timers
// concurrently (each signal has its own batch processor/periodic reader
// running on its own schedule), so all shared state is guarded by mu.
type statusTracker struct {
	mu            sync.Mutex
	states        map[string]signalState
	lastAggregate string
}

func newStatusTracker() *statusTracker {
	return &statusTracker{
		states: map[string]signalState{
			"traces":  statePending,
			"metrics": statePending,
			"logs":    statePending,
		},
	}
}

// track wraps one export attempt for signal with the transition-confirming
// retry described above. attempt must be safe to call more than once with
// the same underlying data - it always is here, since a retry re-sends the
// same batch, not a fresh fetch.
func (t *statusTracker) track(signal string, attempt func() error) error {
	t.mu.Lock()
	current := t.states[signal]
	t.mu.Unlock()

	if current == stateNotWorking {
		// Known-down steady state: single attempt, no retry, no repeat
		// log/report - avoids spamming both during a known outage.
		err := attempt()
		if err == nil {
			t.transitionTo(signal, stateWorking, "")
		}
		return err
	}

	// PENDING (initiating) or WORKING (confirming a possible "stopped
	// working midway"): retry the same payload up to maxAttempts total
	// before declaring the signal not-working.
	var lastErr error
	for attemptNum := 1; attemptNum <= maxAttempts; attemptNum++ {
		lastErr = attempt()
		if lastErr == nil {
			t.transitionTo(signal, stateWorking, "")
			return nil
		}
		if attemptNum < maxAttempts {
			time.Sleep(backoffDelays[attemptNum-1])
		}
	}

	t.transitionTo(signal, stateNotWorking, lastErr.Error())
	return lastErr
}

func (t *statusTracker) transitionTo(signal string, newState signalState, reason string) {
	t.mu.Lock()
	previous := t.states[signal]
	if previous == newState {
		t.mu.Unlock()
		return
	}
	t.states[signal] = newState

	switch newState {
	case stateWorking:
		fmt.Printf("[Owl24] %s working\n", signal)
	case stateNotWorking:
		fmt.Printf("[Owl24] %s not working because: %s\n", signal, reason)
	}

	aggregate := t.computeAggregateLocked()
	t.mu.Unlock()

	if aggregate != "" {
		fmt.Println(aggregate)
	}
}

// computeAggregateLocked must be called with mu held. It returns the new
// aggregate line to print, or "" if nothing should be printed (either
// because not all 3 signals have resolved out of PENDING yet, or because
// the aggregate hasn't changed since it was last printed).
func (t *statusTracker) computeAggregateLocked() string {
	workingCount := 0
	for _, s := range t.states {
		if s == statePending {
			// Wait until all 3 signals have resolved at least once.
			return ""
		}
		if s == stateWorking {
			workingCount++
		}
	}

	var aggregate string
	switch workingCount {
	case len(t.states):
		aggregate = "[Owl24] engaged fully"
	case 0:
		aggregate = "[Owl24] failed to engage"
	default:
		aggregate = "[Owl24] partially engaged"
	}

	if aggregate == t.lastAggregate {
		return ""
	}
	t.lastAggregate = aggregate
	return aggregate
}

// Three thin wrappers, one per signal, each delegating every call straight
// through to the real exporter except the export call itself, which routes
// through statusTracker.track. Separate types because SpanExporter,
// metric.Exporter, and sdklog.Exporter are unrelated OTel interfaces with no
// common supertype - the actual retry/state-machine logic lives once in
// statusTracker; these just adapt it to each interface's shape.

// statusTrackingSpanExporter wraps a sdktrace.SpanExporter.
type statusTrackingSpanExporter struct {
	delegate sdktrace.SpanExporter
	tracker  *statusTracker
}

func (e *statusTrackingSpanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	return e.tracker.track("traces", func() error {
		return e.delegate.ExportSpans(ctx, spans)
	})
}

func (e *statusTrackingSpanExporter) Shutdown(ctx context.Context) error {
	return e.delegate.Shutdown(ctx)
}

// statusTrackingMetricExporter wraps a metric.Exporter (the push exporter
// interface used by metric.NewPeriodicReader).
type statusTrackingMetricExporter struct {
	delegate metric.Exporter
	tracker  *statusTracker
}

func (e *statusTrackingMetricExporter) Temporality(k metric.InstrumentKind) metricdata.Temporality {
	return e.delegate.Temporality(k)
}

func (e *statusTrackingMetricExporter) Aggregation(k metric.InstrumentKind) metric.Aggregation {
	return e.delegate.Aggregation(k)
}

func (e *statusTrackingMetricExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	return e.tracker.track("metrics", func() error {
		return e.delegate.Export(ctx, rm)
	})
}

func (e *statusTrackingMetricExporter) ForceFlush(ctx context.Context) error {
	return e.delegate.ForceFlush(ctx)
}

func (e *statusTrackingMetricExporter) Shutdown(ctx context.Context) error {
	return e.delegate.Shutdown(ctx)
}

// statusTrackingLogExporter wraps a sdklog.Exporter.
type statusTrackingLogExporter struct {
	delegate sdklog.Exporter
	tracker  *statusTracker
}

func (e *statusTrackingLogExporter) Export(ctx context.Context, records []sdklog.Record) error {
	return e.tracker.track("logs", func() error {
		return e.delegate.Export(ctx, records)
	})
}

func (e *statusTrackingLogExporter) Shutdown(ctx context.Context) error {
	return e.delegate.Shutdown(ctx)
}

func (e *statusTrackingLogExporter) ForceFlush(ctx context.Context) error {
	return e.delegate.ForceFlush(ctx)
}
