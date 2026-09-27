package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type latencyCoreSource struct {
	*fakeCoreSource
	latency    v1.ConnectionLatency
	latencyErr error
	latencyReq v1.ConnectionLatencyRequest
}

func (f *latencyCoreSource) ProbeConnectionLatency(_ context.Context, req v1.ConnectionLatencyRequest) (v1.ConnectionLatency, error) {
	f.latencyReq = req
	return f.latency, f.latencyErr
}

func TestServeConnectionLatencyReturnsSanitizedRTT(t *testing.T) {
	source := &latencyCoreSource{
		fakeCoreSource: &fakeCoreSource{},
		latency:        v1.ConnectionLatency{ConnectionID: "conn_abc", RTTMicros: 2450},
	}
	input := `{"op":"connection-latency","request":{"id":"conn_abc"}}` + "\n"
	var out bytes.Buffer
	if err := run([]string{"serve"}, strings.NewReader(input), &out, source); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if source.latencyReq.ConnectionID != "conn_abc" || !strings.Contains(got, `"rtt_micros":2450`) {
		t.Fatalf("request=%#v output=%q", source.latencyReq, got)
	}
	for _, forbidden := range []string{"endpoint", "fingerprint", "route", "device_id"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("latency output %q contains forbidden field %q", got, forbidden)
		}
	}
}

func TestServeConnectionLatencySanitizesCoreError(t *testing.T) {
	source := &latencyCoreSource{
		fakeCoreSource: &fakeCoreSource{},
		latencyErr:     errors.New("sensitive transport timing detail"),
	}
	input := `{"op":"connection-latency","request":{"id":"conn_abc"}}` + "\n"
	var out bytes.Buffer
	if err := run([]string{"serve"}, strings.NewReader(input), &out, source); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, `"ok":false`) || strings.Contains(got, "sensitive transport timing detail") {
		t.Fatalf("output = %q", got)
	}
}
