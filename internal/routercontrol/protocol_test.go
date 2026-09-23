package routercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type protocolTestRouter struct {
	mu       sync.Mutex
	policy   v1.RouterPolicy
	stats    v1.RouterStats
	setErr   error
	getErr   error
	statsErr error
}

func (r *protocolTestRouter) GetRouterPolicy(context.Context) (v1.RouterPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.policy, r.getErr
}

func (r *protocolTestRouter) SetRouterPolicy(
	_ context.Context,
	req v1.SetRouterPolicyRequest,
) (v1.RouterPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.setErr != nil {
		return v1.RouterPolicy{}, r.setErr
	}
	r.policy = req.Policy
	return r.policy, nil
}

func (r *protocolTestRouter) GetRouterStats(context.Context) (v1.RouterStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats, r.statsErr
}

func protocolTestDialer(server *ProtocolServer) DialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		go func() {
			defer serverSide.Close()
			_ = server.ServeOne(ctx, serverSide)
		}()
		return clientSide, nil
	}
}

func TestProtocolClientRoundTrip(t *testing.T) {
	t.Parallel()

	service := &protocolTestRouter{
		policy: v1.RouterPolicy{
			Enabled:            true,
			TrustedDevicesOnly: true,
			MaxSessions:        4,
		},
		stats: v1.RouterStats{
			ActiveSessions:    1,
			BytesForwarded:    1234,
			SessionsForwarded: 9,
		},
	}
	server := &ProtocolServer{Service: service}
	client := &Client{Dial: protocolTestDialer(server)}

	policy, err := client.GetRouterPolicy(context.Background())
	if err != nil {
		t.Fatalf("GetRouterPolicy() error: %v", err)
	}
	if policy != service.policy {
		t.Fatalf("policy = %+v, want %+v", policy, service.policy)
	}

	wantPolicy := v1.RouterPolicy{
		Enabled:            false,
		TrustedDevicesOnly: true,
		MaxSessions:        2,
		LANOnly:            true,
	}
	policy, err = client.SetRouterPolicy(
		context.Background(),
		v1.SetRouterPolicyRequest{Policy: wantPolicy},
	)
	if err != nil {
		t.Fatalf("SetRouterPolicy() error: %v", err)
	}
	if policy != wantPolicy {
		t.Fatalf("SetRouterPolicy() = %+v, want %+v", policy, wantPolicy)
	}

	stats, err := client.GetRouterStats(context.Background())
	if err != nil {
		t.Fatalf("GetRouterStats() error: %v", err)
	}
	if stats != service.stats {
		t.Fatalf("stats = %+v, want %+v", stats, service.stats)
	}
}

func TestProtocolClientMapsStableErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{"invalid", coreapi.ErrInvalidRouterPolicy, coreapi.ErrInvalidRouterPolicy},
		{"unavailable", coreapi.ErrRouterUnavailable, coreapi.ErrRouterUnavailable},
		{"operation", coreapi.ErrRouterOperation, coreapi.ErrRouterOperation},
		{"private", errors.New("private backend detail"), coreapi.ErrRouterOperation},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &protocolTestRouter{getErr: test.err}
			server := &ProtocolServer{Service: service}
			client := &Client{Dial: protocolTestDialer(server)}

			_, err := client.GetRouterPolicy(context.Background())
			if !errors.Is(err, test.want) {
				t.Fatalf("GetRouterPolicy() error = %v, want %v", err, test.want)
			}
			if err != nil && strings.Contains(err.Error(), "private backend detail") {
				t.Fatalf("client error leaked backend detail: %v", err)
			}
		})
	}
}

func TestProtocolServerRejectsNonRouterMethod(t *testing.T) {
	t.Parallel()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	server := &ProtocolServer{Service: &protocolTestRouter{}}
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		done <- server.ServeOne(context.Background(), serverSide)
	}()

	if err := ipc.WriteRequest(clientSide, ipc.Request{
		Version: v1.Version,
		ID:      "not-router",
		Method:  v1.MethodStatusGet,
	}); err != nil {
		t.Fatal(err)
	}
	response, err := ipc.ReadResponse(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != ipc.ErrorMethodNotFound {
		t.Fatalf("response = %#v, want method_not_found", response)
	}
	if err := <-done; err != nil {
		t.Fatalf("ServeOne() error: %v", err)
	}
}

func TestProtocolServerStrictlyDecodesPolicySet(t *testing.T) {
	t.Parallel()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	service := &protocolTestRouter{}
	server := &ProtocolServer{Service: service}
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		done <- server.ServeOne(context.Background(), serverSide)
	}()

	params := json.RawMessage(
		`{"policy":{"trusted_devices_only":true},"unexpected":true}`,
	)
	if err := ipc.WriteRequest(clientSide, ipc.Request{
		Version: v1.Version,
		ID:      "strict",
		Method:  v1.MethodRouterPolicySet,
		Params:  params,
	}); err != nil {
		t.Fatal(err)
	}
	response, err := ipc.ReadResponse(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || response.Error.Code != ipc.ErrorInvalidParams {
		t.Fatalf("response = %#v, want invalid_params", response)
	}
	if err := <-done; err != nil {
		t.Fatalf("ServeOne() error: %v", err)
	}
}

func TestProtocolClientFailsClosedWithoutDialer(t *testing.T) {
	t.Parallel()

	var client *Client
	if _, err := client.GetRouterPolicy(context.Background()); !errors.Is(err, coreapi.ErrRouterUnavailable) {
		t.Fatalf("GetRouterPolicy() error = %v", err)
	}
}
