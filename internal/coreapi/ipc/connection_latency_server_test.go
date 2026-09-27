package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeConnectionLatencyIPCService struct {
	fakeConnectionIPCService
	latencyReq v1.ConnectionLatencyRequest
	latency    v1.ConnectionLatency
	latencyErr error
}

func (f *fakeConnectionLatencyIPCService) ProbeConnectionLatency(_ context.Context, req v1.ConnectionLatencyRequest) (v1.ConnectionLatency, error) {
	f.latencyReq = req
	return f.latency, f.latencyErr
}

func TestServerConnectionLatencyDispatchesOverConnectionService(t *testing.T) {
	read := &fakeReadService{}
	measuredAt := time.Date(2026, 9, 26, 23, 59, 0, 0, time.UTC)
	connections := &fakeConnectionLatencyIPCService{latency: v1.ConnectionLatency{
		ConnectionID: "conn_test",
		RTTMicros:    4321,
		MeasuredAt:   measuredAt,
	}}
	server, err := NewServerWithServices(Services{
		Status:      read,
		Devices:     read,
		Connections: connections,
	})
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(v1.ConnectionLatencyRequest{ConnectionID: "conn_test"})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "latency-1",
		Method:  v1.MethodConnectionLatency,
		Params:  params,
	})
	if response.Error != nil {
		t.Fatalf("latency response error = %#v", response.Error)
	}
	if connections.latencyReq.ConnectionID != "conn_test" {
		t.Fatalf("latency request = %#v", connections.latencyReq)
	}
	var got v1.ConnectionLatency
	if err := json.Unmarshal(response.Result, &got); err != nil {
		t.Fatal(err)
	}
	if got.ConnectionID != "conn_test" || got.RTTMicros != 4321 || !got.MeasuredAt.Equal(measuredAt) {
		t.Fatalf("latency = %#v", got)
	}
}

func TestServerConnectionLatencyErrorsAreSanitized(t *testing.T) {
	read := &fakeReadService{}
	connections := &fakeConnectionLatencyIPCService{}
	server, err := NewServerWithServices(Services{Status: read, Devices: read, Connections: connections})
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(v1.ConnectionLatencyRequest{ConnectionID: "conn_test"})
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"missing":     {err: coreapi.ErrConnectionNotFound, code: ErrorConnectionNotFound},
		"unavailable": {err: coreapi.ErrConnectionLatencyUnavailable, code: ErrorConnectionLatencyUnavailable},
		"failed":      {err: errors.Join(coreapi.ErrConnectionLatencyOperation, errors.New("sensitive latency backend detail")), code: ErrorConnectionLatencyFailed},
	} {
		t.Run(name, func(t *testing.T) {
			connections.latencyErr = tc.err
			response := serve(t, server, Request{
				Version: v1.Version,
				ID:      "latency-error",
				Method:  v1.MethodConnectionLatency,
				Params:  params,
			})
			if response.Error == nil || response.Error.Code != tc.code {
				t.Fatalf("response = %#v, want %q", response, tc.code)
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "sensitive latency backend detail") {
				t.Fatalf("response leaked backend detail: %s", encoded)
			}
		})
	}
}

func TestServerConnectionLatencyRequiresMetricsCapability(t *testing.T) {
	read := &fakeReadService{}
	server, err := NewServerWithServices(Services{
		Status:      read,
		Devices:     read,
		Connections: &fakeConnectionIPCService{},
	})
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(v1.ConnectionLatencyRequest{ConnectionID: "conn_test"})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "latency-disabled",
		Method:  v1.MethodConnectionLatency,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("response = %#v", response)
	}
}
