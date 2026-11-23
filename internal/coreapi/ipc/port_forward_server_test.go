package ipc

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/portforward"
)

type fakePortForwardService struct {
	starts int
	stops  []string
	status []v1.PortForwardStatus
}

func (s *fakePortForwardService) StartPortForward(_ context.Context, _ v1.PortForwardStartRequest) (v1.PortForwardStatus, error) {
	s.starts++
	return v1.PortForwardStatus{ID: "00000000-0000-4000-8000-000000000001", Direction: portforward.DirectionLocal, ExpiresAt: time.Unix(1, 0)}, nil
}

func (s *fakePortForwardService) StopPortForward(_ context.Context, req v1.PortForwardStopRequest) error {
	s.stops = append(s.stops, req.ForwardingID)
	return nil
}

func (s *fakePortForwardService) GetPortForwardStatus(_ context.Context, req v1.PortForwardStatusRequest) (v1.PortForwardStatus, error) {
	for _, status := range s.status {
		if status.ID == req.ForwardingID {
			return status, nil
		}
	}
	return v1.PortForwardStatus{}, nil
}

func (s *fakePortForwardService) ListPortForwards(context.Context) ([]v1.PortForwardStatus, error) {
	return append([]v1.PortForwardStatus(nil), s.status...), nil
}

func TestPortForwardIPCExposesOnlySignedLifecycleOperations(t *testing.T) {
	fake := &fakePortForwardService{
		status: []v1.PortForwardStatus{{ID: "00000000-0000-4000-8000-000000000001", Direction: portforward.DirectionLocal}},
	}
	server := &Server{portForwarding: fake}
	startParams, err := json.Marshal(v1.PortForwardStartRequest{})
	if err != nil {
		t.Fatal(err)
	}
	start := server.handle(context.Background(), Request{
		Version: v1.Version, ID: "1", Method: v1.MethodPortForwardStart, Params: startParams,
	})
	if start.Error != nil || fake.starts != 1 {
		t.Fatalf("port_forward.start response = %#v, starts = %d", start.Error, fake.starts)
	}

	stopParams, err := json.Marshal(v1.PortForwardStopRequest{ForwardingID: "00000000-0000-4000-8000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	stop := server.handle(context.Background(), Request{
		Version: v1.Version, ID: "2", Method: v1.MethodPortForwardStop, Params: stopParams,
	})
	if stop.Error != nil || len(fake.stops) != 1 || fake.stops[0] != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("port_forward.stop response = %#v, stops = %#v", stop.Error, fake.stops)
	}

	statusParams, err := json.Marshal(v1.PortForwardStatusRequest{ForwardingID: fake.status[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	statusResponse := server.handle(context.Background(), Request{
		Version: v1.Version, ID: "3", Method: v1.MethodPortForwardStatus, Params: statusParams,
	})
	if statusResponse.Error != nil {
		t.Fatalf("port_forward.status error = %#v", statusResponse.Error)
	}
	var oneStatus v1.PortForwardStatus
	if err := json.Unmarshal(statusResponse.Result, &oneStatus); err != nil {
		t.Fatal(err)
	}
	if oneStatus.ID != fake.status[0].ID {
		t.Fatalf("port_forward.status result = %#v", oneStatus)
	}

	list := server.handle(context.Background(), Request{
		Version: v1.Version, ID: "3", Method: v1.MethodPortForwardList,
	})
	if list.Error != nil {
		t.Fatalf("port_forward.list error = %#v", list.Error)
	}
	var status []v1.PortForwardStatus
	if err := json.Unmarshal(list.Result, &status); err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0].ID != fake.status[0].ID {
		t.Fatalf("port_forward.list result = %#v", status)
	}
}

func TestPortForwardIPCIsUnavailableWhenCoreHasNoManager(t *testing.T) {
	server := &Server{}
	response := server.handle(context.Background(), Request{
		Version: v1.Version, ID: "1", Method: v1.MethodPortForwardList,
	})
	if response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("port_forward.list without manager = %#v, want method_not_found", response.Error)
	}
}
