// Package v1 defines the stable, transport-neutral contract exposed by the
// WeDecent core to local user interfaces.
package v1

import (
	"context"
	"time"
)

const Version = "v1"

const (
	MethodStatusGet            = "status.get"
	MethodDevicesList          = "devices.list"
	MethodDeviceGet            = "device.get"
	MethodAccountSignIn        = "account.sign_in"
	MethodAccountSignOut       = "account.sign_out"
	MethodConnectionConnect    = "connection.connect"
	MethodConnectionDisconnect = "connection.disconnect"
	MethodTransportsList       = "transports.list"
	MethodRouteGet             = "route.get"
)

type ConnectionPath string

const (
	ConnectionPathDirect ConnectionPath = "direct"
	ConnectionPathLAN    ConnectionPath = "lan"
	ConnectionPathRouted ConnectionPath = "routed"
	ConnectionPathRelay  ConnectionPath = "relay"
)

type ConnectionState string

const (
	ConnectionStateConnecting ConnectionState = "connecting"
	ConnectionStateConnected  ConnectionState = "connected"
	ConnectionStateClosed     ConnectionState = "closed"
)

type TransportName string

const (
	TransportLAN       TransportName = "lan"
	TransportInternet  TransportName = "internet"
	TransportBluetooth TransportName = "bluetooth"
)

type Status struct {
	APIVersion string `json:"api_version"`
	SignedIn   bool   `json:"signed_in"`
	UserID     string `json:"user_id,omitempty"`
	Email      string `json:"email,omitempty"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
}

type Device struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Endpoint    string `json:"endpoint,omitempty"`
}

type TransportStatus struct {
	Name      TransportName `json:"name"`
	Available bool          `json:"available"`
	Detail    string        `json:"detail,omitempty"`
}

type Connection struct {
	ID        string          `json:"id"`
	DeviceID  string          `json:"device_id"`
	State     ConnectionState `json:"state"`
	Path      ConnectionPath  `json:"path"`
	StartedAt time.Time       `json:"started_at"`
}

type RouteHop struct {
	From      string        `json:"from"`
	To        string        `json:"to"`
	Transport TransportName `json:"transport"`
	Cost      uint64        `json:"cost"`
}

type RouteStatus struct {
	ConnectionID  string         `json:"connection_id"`
	DestinationID string         `json:"destination_id"`
	Path          ConnectionPath `json:"path"`
	RouterID      string         `json:"router_id,omitempty"`
	Hops          []RouteHop     `json:"hops,omitempty"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"`
}

type RouterPolicy struct {
	Enabled                 bool  `json:"enabled"`
	TrustedDevicesOnly      bool  `json:"trusted_devices_only"`
	OrganizationOnly        bool  `json:"organization_only"`
	PublicRouting           bool  `json:"public_routing"`
	MaxSessions             int   `json:"max_sessions"`
	MaxBandwidthBytesPerSec int64 `json:"max_bandwidth_bytes_per_sec"`
	AllowOnBattery          bool  `json:"allow_on_battery"`
	AllowMetered            bool  `json:"allow_metered"`
	LANOnly                 bool  `json:"lan_only"`
}

type RouterStats struct {
	ActiveSessions    int    `json:"active_sessions"`
	BytesForwarded    uint64 `json:"bytes_forwarded"`
	SessionsForwarded uint64 `json:"sessions_forwarded"`
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type GetDeviceRequest struct {
	DeviceID string `json:"device_id"`
}

type ConnectRequest struct {
	DeviceID string `json:"device_id"`
}

type DisconnectRequest struct {
	ConnectionID string `json:"connection_id"`
}

type GetRouteStatusRequest struct {
	ConnectionID string `json:"connection_id"`
}

type SetRouterPolicyRequest struct {
	Policy RouterPolicy `json:"policy"`
}

type StatusService interface {
	GetStatus(context.Context) (Status, error)
}

type AccountService interface {
	SignIn(context.Context, SignInRequest) (Status, error)
	SignOut(context.Context) error
}

type DeviceService interface {
	ListDevices(context.Context) ([]Device, error)
	GetDevice(context.Context, GetDeviceRequest) (Device, error)
}

type ConnectionService interface {
	Connect(context.Context, ConnectRequest) (Connection, error)
	Disconnect(context.Context, DisconnectRequest) error
}

type TransportService interface {
	GetTransportStatus(context.Context) ([]TransportStatus, error)
}

type RouteService interface {
	GetRouteStatus(context.Context, GetRouteStatusRequest) (RouteStatus, error)
}

type RouterService interface {
	GetRouterPolicy(context.Context) (RouterPolicy, error)
	SetRouterPolicy(context.Context, SetRouterPolicyRequest) (RouterPolicy, error)
	GetRouterStats(context.Context) (RouterStats, error)
}

// Service is the UI-facing boundary of the local core. Implementations own
// identity, authorization, route selection, transport choice, and session crypto.
// Account credentials are accepted only as request data over the protected local
// transport; access and refresh tokens are never response fields.
type Service interface {
	StatusService
	AccountService
	DeviceService
	ConnectionService
	TransportService
	RouteService
	RouterService
}
