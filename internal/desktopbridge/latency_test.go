package desktopbridge

import (
	"context"
	"errors"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeLatencySource struct {
	result v1.ConnectionLatency
	err    error
	req    v1.ConnectionLatencyRequest
}

func (f *fakeLatencySource) ProbeConnectionLatency(_ context.Context, req v1.ConnectionLatencyRequest) (v1.ConnectionLatency, error) {
	f.req = req
	return f.result, f.err
}

func TestProbeConnectionLatencyReturnsOnlyValidatedRTT(t *testing.T) {
	source := &fakeLatencySource{result: v1.ConnectionLatency{ConnectionID: "conn_abc", RTTMicros: 1234}}
	got, err := ProbeConnectionLatency(context.Background(), source, "conn_abc")
	if err != nil {
		t.Fatal(err)
	}
	if source.req.ConnectionID != "conn_abc" || got.RTTMicros != 1234 {
		t.Fatalf("request=%#v result=%#v", source.req, got)
	}
}

func TestProbeConnectionLatencyRejectsMismatchedOrEmptyCoreResult(t *testing.T) {
	for name, result := range map[string]v1.ConnectionLatency{
		"mismatched id": {ConnectionID: "conn_other", RTTMicros: 10},
		"zero rtt":      {ConnectionID: "conn_abc", RTTMicros: 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ProbeConnectionLatency(context.Background(), &fakeLatencySource{result: result}, "conn_abc")
			if !errors.Is(err, ErrInvalidTerminalBridgeRequest) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestProbeConnectionLatencyRejectsInvalidIDBeforeCoreCall(t *testing.T) {
	source := &fakeLatencySource{}
	_, err := ProbeConnectionLatency(context.Background(), source, "bad id")
	if !errors.Is(err, ErrInvalidTerminalBridgeRequest) {
		t.Fatalf("error = %v", err)
	}
	if source.req.ConnectionID != "" {
		t.Fatalf("Core was called with %#v", source.req)
	}
}

func TestProbeConnectionLatencyPropagatesCoreError(t *testing.T) {
	want := errors.New("core latency failed")
	_, err := ProbeConnectionLatency(context.Background(), &fakeLatencySource{err: want}, "conn_abc")
	if !errors.Is(err, want) {
		t.Fatalf("error = %v", err)
	}
}
