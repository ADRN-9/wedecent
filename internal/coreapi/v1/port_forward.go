package v1

import (
	"context"
	"time"

	"wedecent.com/wedecent/internal/portforward"
)

const (
	MethodPortForwardStart = "port_forward.start"
	MethodPortForwardStop  = "port_forward.stop"
	MethodPortForwardList  = "port_forward.list"
)

type PortForwardStatus struct {
	ID                 string                  `json:"id"`
	Direction          portforward.Direction   `json:"direction"`
	ListenerAddress    string                  `json:"listener_address"`
	DestinationAddress string                  `json:"destination_address"`
	DestinationPort    uint16                  `json:"destination_port"`
	ExpiresAt          time.Time               `json:"expires_at"`
	ActiveConnections  int                     `json:"active_connections"`
}

type PortForwardStartRequest struct {
	Authorization portforward.Authorization `json:"authorization"`
}

type PortForwardStopRequest struct {
	ForwardingID string `json:"forwarding_id"`
}

// PortForwardService accepts only signed capabilities. Local Core retains
// authorization, listener, networking and secret authority.
type PortForwardService interface {
	StartPortForward(context.Context, PortForwardStartRequest) (PortForwardStatus, error)
	StopPortForward(context.Context, PortForwardStopRequest) error
	ListPortForwards(context.Context) ([]PortForwardStatus, error)
}
