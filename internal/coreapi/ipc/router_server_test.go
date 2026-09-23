package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeRouterService struct {
	policy   v1.RouterPolicy
	stats    v1.RouterStats
	getErr   error
	setErr   error
	statsErr error
	setCalls int
	lastSet  v1.SetRouterPolicyRequest
}

func (f *fakeRouterService) GetRouterPolicy(context.Context) (v1.RouterPolicy, error) {
	return f.policy, f.getErr
}

func (f *fakeRouterService) SetRouterPolicy(_ context.Context, req v1.SetRouterPolicyRequest) (v1.RouterPolicy, error) {
	f.setCalls++
	f.lastSet = req
	if f.setErr != nil {
		return v1.RouterPolicy{}, f.setErr
	}
	f.policy = req.Policy
	return f.policy, nil
}

func (f *fakeRouterService) GetRouterStats(context.Context) (v1.RouterStats, error) {
	return f.stats, f.statsErr
}

func newRouterTestServer(t *testing.T, router v1.RouterService) *Server {
	t.Helper()
	read := &fakeReadService{}
	server, err := NewServerWithServices(Services{
		Status:  read,
		Devices: read,
		Router:  router,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestServerRouterPolicyGetSetAndStats(t *testing.T) {
	router := &fakeRouterService{
		policy: v1.RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
			MaxSessions:        4,
		},
		stats: v1.RouterStats{
			ActiveSessions:    1,
			BytesForwarded:    42,
			SessionsForwarded: 3,
		},
	}
	server := newRouterTestServer(t, router)

	getResponse := serve(t, server, Request{
		Version: v1.Version,
		ID:      "router-get",
		Method:  v1.MethodRouterPolicyGet,
	})
	if getResponse.Error != nil {
		t.Fatalf("policy get error = %#v", getResponse.Error)
	}
	var gotPolicy v1.RouterPolicy
	if err := json.Unmarshal(getResponse.Result, &gotPolicy); err != nil {
		t.Fatal(err)
	}
	if gotPolicy != router.policy {
		t.Fatalf("policy = %+v, want %+v", gotPolicy, router.policy)
	}

	wantPolicy := v1.RouterPolicy{
		Enabled:            false,
		TrustedDevicesOnly: true,
		MaxSessions:        2,
		LANOnly:            true,
	}
	params, err := json.Marshal(v1.SetRouterPolicyRequest{Policy: wantPolicy})
	if err != nil {
		t.Fatal(err)
	}
	setResponse := serve(t, server, Request{
		Version: v1.Version,
		ID:      "router-set",
		Method:  v1.MethodRouterPolicySet,
		Params:  params,
	})
	if setResponse.Error != nil {
		t.Fatalf("policy set error = %#v", setResponse.Error)
	}
	if router.setCalls != 1 || router.lastSet.Policy != wantPolicy {
		t.Fatalf("router set calls = %d, last = %+v", router.setCalls, router.lastSet)
	}
	if err := json.Unmarshal(setResponse.Result, &gotPolicy); err != nil {
		t.Fatal(err)
	}
	if gotPolicy != wantPolicy {
		t.Fatalf("set policy result = %+v, want %+v", gotPolicy, wantPolicy)
	}

	statsResponse := serve(t, server, Request{
		Version: v1.Version,
		ID:      "router-stats",
		Method:  v1.MethodRouterStatsGet,
	})
	if statsResponse.Error != nil {
		t.Fatalf("stats error = %#v", statsResponse.Error)
	}
	var gotStats v1.RouterStats
	if err := json.Unmarshal(statsResponse.Result, &gotStats); err != nil {
		t.Fatal(err)
	}
	if gotStats != router.stats {
		t.Fatalf("stats = %+v, want %+v", gotStats, router.stats)
	}
}

func TestServerRouterMethodsRemainUncomposedByDefault(t *testing.T) {
	server := newRouterTestServer(t, nil)

	for i, method := range []string{
		v1.MethodRouterPolicyGet,
		v1.MethodRouterPolicySet,
		v1.MethodRouterStatsGet,
	} {
		req := Request{
			Version: v1.Version,
			ID:      "router-missing",
			Method:  method,
		}
		if method == v1.MethodRouterPolicySet {
			req.Params = json.RawMessage(`{"policy":{"trusted_devices_only":true}}`)
		}
		response := serve(t, server, req)
		if response.Error == nil || response.Error.Code != ErrorMethodNotFound {
			t.Fatalf("case %d response = %#v", i, response)
		}
	}
}

func TestServerRouterSetDecodesStrictParams(t *testing.T) {
	router := &fakeRouterService{}
	server := newRouterTestServer(t, router)
	response := serve(t, server, Request{
		Version: v1.Version,
		ID:      "router-strict",
		Method:  v1.MethodRouterPolicySet,
		Params: json.RawMessage(
			`{"policy":{"trusted_devices_only":true},"unexpected":true}`,
		),
	})
	if response.Error == nil || response.Error.Code != ErrorInvalidParams {
		t.Fatalf("response = %#v", response)
	}
	if router.setCalls != 0 {
		t.Fatalf("router set called %d times after invalid params", router.setCalls)
	}
}

func TestServerMapsRouterErrorsWithoutLeakingDetails(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
	}{
		{"invalid", coreapi.ErrInvalidRouterPolicy, ErrorInvalidParams},
		{"unavailable", coreapi.ErrRouterUnavailable, ErrorRouterUnavailable},
		{"operation", coreapi.ErrRouterOperation, ErrorRouterFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := &fakeRouterService{
				getErr: errors.Join(test.err, errors.New("private backend detail")),
			}
			server := newRouterTestServer(t, router)
			response := serve(t, server, Request{
				Version: v1.Version,
				ID:      "router-error",
				Method:  v1.MethodRouterPolicyGet,
			})
			if response.Error == nil || response.Error.Code != test.code {
				t.Fatalf("response = %#v", response)
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) == "" || containsPrivateRouterDetail(string(encoded)) {
				t.Fatalf("response leaked backend detail: %s", encoded)
			}
		})
	}
}

func containsPrivateRouterDetail(value string) bool {
	return len(value) >= len("private backend detail") &&
		json.Valid([]byte(value)) &&
		contains(value, "private backend detail")
}

func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
