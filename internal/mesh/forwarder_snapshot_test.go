package mesh

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func waitForForwarderSnapshot(
	t *testing.T,
	forwarder *Forwarder,
	match func(ForwarderSnapshot) bool,
) ForwarderSnapshot {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		snapshot := forwarder.Snapshot()
		if match(snapshot) {
			return snapshot
		}
		if time.Now().After(deadline) {
			t.Fatalf("forwarder snapshot did not reach expected state: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestForwarderSnapshotTracksAcceptedForwarding(t *testing.T) {
	t.Parallel()

	clientSide, routerIncoming := net.Pipe()
	routerOutgoing, targetSide := net.Pipe()

	defer targetSide.Close()

	dialed := make(chan struct{})
	policy := RouterPolicy{
		Enabled:            true,
		TrustedDevicesOnly: true,
		MaxSessions:        2,
	}
	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy:  policy,
		Authorizer: forwardAuthorizerFunc(func(context.Context, ForwardRequest) error {
			return nil
		}),
		DialNext: func(context.Context, RouteHop) (Link, error) {
			close(dialed)
			return &testMeshLink{
				Conn:      routerOutgoing,
				local:     "wd_b",
				remote:    "wd_c",
				transport: TransportInternet,
			}, nil
		},
	}

	type forwardResponse struct {
		result ForwardResult
		err    error
	}
	forwardDone := make(chan forwardResponse, 1)
	go func() {
		result, err := forwarder.Forward(
			context.Background(),
			oneHopTestRoute(time.Now().Add(time.Minute)),
			&testMeshLink{
				Conn:      routerIncoming,
				local:     "wd_b",
				remote:    "wd_a",
				transport: TransportLAN,
			},
		)
		forwardDone <- forwardResponse{result: result, err: err}
	}()

	select {
	case <-dialed:
	case <-time.After(2 * time.Second):
		t.Fatal("destination was not dialed")
	}

	snapshot := waitForForwarderSnapshot(t, forwarder, func(snapshot ForwarderSnapshot) bool {
		return snapshot.Stats.ActiveSessions == 1 &&
			snapshot.Stats.SessionsForwarded == 1
	})
	if snapshot.Policy != policy {
		t.Fatalf("snapshot policy = %+v, want %+v", snapshot.Policy, policy)
	}
	if snapshot.Stats.BytesForwarded != 0 {
		t.Fatalf("bytes forwarded while session is active = %d, want 0 before completion", snapshot.Stats.BytesForwarded)
	}

	const request = "router-stats-request"
	const response = "router-stats-response"

	targetDone := make(chan error, 1)
	go func() {
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(targetSide, buf); err != nil {
			targetDone <- err
			return
		}
		if string(buf) != request {
			targetDone <- errors.New("target received altered bytes")
			return
		}
		if _, err := targetSide.Write([]byte(response)); err != nil {
			targetDone <- err
			return
		}
		targetDone <- nil
	}()

	if _, err := clientSide.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	buf := make([]byte, len(response))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(buf) != response {
		t.Fatalf("response = %q, want %q", buf, response)
	}
	if err := <-targetDone; err != nil {
		t.Fatalf("target exchange: %v", err)
	}

	_ = clientSide.Close()

	got := <-forwardDone
	if got.err != nil {
		t.Fatalf("Forward() error: %v", got.err)
	}

	snapshot = forwarder.Snapshot()
	if snapshot.Stats.ActiveSessions != 0 {
		t.Fatalf("active sessions = %d after close, want 0", snapshot.Stats.ActiveSessions)
	}
	if snapshot.Stats.SessionsForwarded != 1 {
		t.Fatalf("sessions forwarded = %d, want 1", snapshot.Stats.SessionsForwarded)
	}
	wantBytes := uint64(len(request) + len(response))
	if snapshot.Stats.BytesForwarded != wantBytes {
		t.Fatalf("bytes forwarded = %d, want %d", snapshot.Stats.BytesForwarded, wantBytes)
	}
}

func TestForwarderSnapshotDoesNotCountRejectedRoute(t *testing.T) {
	t.Parallel()

	routerSide, peerSide := net.Pipe()
	defer peerSide.Close()

	forwarder := &Forwarder{
		LocalID: "wd_b",
		Policy:  DisabledRouterPolicy(),
	}

	_, err := forwarder.Forward(
		context.Background(),
		oneHopTestRoute(time.Now().Add(time.Minute)),
		&testMeshLink{
			Conn:      routerSide,
			local:     "wd_b",
			remote:    "wd_a",
			transport: TransportLAN,
		},
	)
	if !errors.Is(err, ErrRoutingDisabled) {
		t.Fatalf("Forward() error = %v, want ErrRoutingDisabled", err)
	}

	snapshot := forwarder.Snapshot()
	if snapshot.Stats != (ForwarderStats{}) {
		t.Fatalf("rejected route changed stats: %+v", snapshot.Stats)
	}
}

func TestSaturatingAddUint64(t *testing.T) {
	t.Parallel()

	const maxUint64 = ^uint64(0)
	if got := saturatingAddUint64(maxUint64-1, 2); got != maxUint64 {
		t.Fatalf("saturatingAddUint64 overflow = %d, want %d", got, maxUint64)
	}
	if got := saturatingAddUint64(40, 2); got != 42 {
		t.Fatalf("saturatingAddUint64 normal sum = %d, want 42", got)
	}
}
