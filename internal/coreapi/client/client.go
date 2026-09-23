// Package client provides the typed UI-side client for the Local Core v1 API.
// Each method uses exactly one protected local IPC connection and one bounded
// request/response exchange.
package client

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/coreapi/ipc"
	"wedecent.com/wedecent/internal/coreapi/localipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const (
	DefaultTimeout = 10 * time.Second
	maxTimeout     = time.Minute
)

var (
	ErrInvalidConfig      = errors.New("core client: invalid configuration")
	ErrMismatchedResponse = errors.New("core client: mismatched response")
)

type DialFunc func(context.Context) (net.Conn, error)

type Config struct {
	Dial    DialFunc
	Timeout time.Duration
	Random  io.Reader
}

// RemoteError is a stable, already-sanitized error returned by Local Core.
// It intentionally contains only the public protocol code and message.
type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

func (e *RemoteError) IsCode(code string) bool {
	return e != nil && e.Code == code
}

type Client struct {
	dial    DialFunc
	timeout time.Duration
	random  io.Reader

	randomMu sync.Mutex
}

var _ v1.Service = (*Client)(nil)

func New(cfg Config) (*Client, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout <= 0 || timeout > maxTimeout {
		return nil, fmt.Errorf("%w: timeout must be between 1ns and %s", ErrInvalidConfig, maxTimeout)
	}
	dial := cfg.Dial
	if dial == nil {
		dial = localipc.Dial
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	return &Client{dial: dial, timeout: timeout, random: random}, nil
}

func (c *Client) GetStatus(ctx context.Context) (v1.Status, error) {
	var out v1.Status
	err := c.call(ctx, v1.MethodStatusGet, nil, &out)
	return out, err
}

func (c *Client) SignIn(ctx context.Context, req v1.SignInRequest) (v1.Status, error) {
	var out v1.Status
	err := c.call(ctx, v1.MethodAccountSignIn, req, &out)
	return out, err
}

func (c *Client) SignOut(ctx context.Context) error {
	return c.call(ctx, v1.MethodAccountSignOut, nil, nil)
}

func (c *Client) ListDevices(ctx context.Context) ([]v1.Device, error) {
	var out []v1.Device
	err := c.call(ctx, v1.MethodDevicesList, nil, &out)
	return out, err
}

func (c *Client) GetDevice(ctx context.Context, req v1.GetDeviceRequest) (v1.Device, error) {
	var out v1.Device
	err := c.call(ctx, v1.MethodDeviceGet, req, &out)
	return out, err
}

func (c *Client) Connect(ctx context.Context, req v1.ConnectRequest) (v1.Connection, error) {
	var out v1.Connection
	err := c.call(ctx, v1.MethodConnectionConnect, req, &out)
	return out, err
}

func (c *Client) Disconnect(ctx context.Context, req v1.DisconnectRequest) error {
	return c.call(ctx, v1.MethodConnectionDisconnect, req, nil)
}

func (c *Client) ReadTerminal(ctx context.Context, req v1.TerminalReadRequest) (v1.TerminalReadResult, error) {
	var out v1.TerminalReadResult
	err := c.call(ctx, v1.MethodTerminalRead, req, &out)
	return out, err
}

func (c *Client) WriteTerminal(ctx context.Context, req v1.TerminalWriteRequest) error {
	return c.call(ctx, v1.MethodTerminalWrite, req, nil)
}

func (c *Client) ResizeTerminal(ctx context.Context, req v1.TerminalResizeRequest) error {
	return c.call(ctx, v1.MethodTerminalResize, req, nil)
}

func (c *Client) GetTransportStatus(ctx context.Context) ([]v1.TransportStatus, error) {
	var out []v1.TransportStatus
	err := c.call(ctx, v1.MethodTransportsList, nil, &out)
	return out, err
}

func (c *Client) GetRouteStatus(ctx context.Context, req v1.GetRouteStatusRequest) (v1.RouteStatus, error) {
	var out v1.RouteStatus
	err := c.call(ctx, v1.MethodRouteGet, req, &out)
	return out, err
}

func (c *Client) GetRouterPolicy(ctx context.Context) (v1.RouterPolicy, error) {
	var out v1.RouterPolicy
	err := c.call(ctx, v1.MethodRouterPolicyGet, nil, &out)
	return out, err
}

func (c *Client) SetRouterPolicy(ctx context.Context, req v1.SetRouterPolicyRequest) (v1.RouterPolicy, error) {
	var out v1.RouterPolicy
	err := c.call(ctx, v1.MethodRouterPolicySet, req, &out)
	return out, err
}

func (c *Client) GetRouterStats(ctx context.Context) (v1.RouterStats, error) {
	var out v1.RouterStats
	err := c.call(ctx, v1.MethodRouterStatsGet, nil, &out)
	return out, err
}

func (c *Client) call(parent context.Context, method string, params any, out any) error {
	if parent == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidConfig)
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}

	requestID, err := c.newRequestID()
	if err != nil {
		return fmt.Errorf("core client: generate request id: %w", err)
	}

	var encoded json.RawMessage
	if params != nil {
		encoded, err = json.Marshal(params)
		if err != nil {
			return fmt.Errorf("core client: encode request: %w", err)
		}
		defer wipe(encoded)
	}

	conn, err := c.dial(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return unavailableError(UnavailableStageDial)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return unavailableError(UnavailableStageSetDeadline)
		}
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopCancel()

	req := ipc.Request{Version: v1.Version, ID: requestID, Method: method, Params: encoded}
	if err := ipc.WriteRequest(conn, req); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(ctxErr, unavailableError(UnavailableStageWriteRequest))
		}
		if errors.Is(err, ipc.ErrInvalidMessage) || errors.Is(err, ipc.ErrFrameTooLarge) {
			return fmt.Errorf("core client: write request: %w", err)
		}
		return unavailableError(UnavailableStageWriteRequest)
	}

	response, err := ipc.ReadResponse(conn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(ctxErr, unavailableError(UnavailableStageReadResponse))
		}
		if errors.Is(err, ipc.ErrInvalidMessage) || errors.Is(err, ipc.ErrFrameTooLarge) {
			return fmt.Errorf("core client: read response: %w", err)
		}
		return unavailableError(UnavailableStageReadResponse)
	}
	defer wipe(response.Result)
	if response.ID != requestID {
		return ErrMismatchedResponse
	}
	if response.Error != nil {
		return &RemoteError{Code: response.Error.Code, Message: response.Error.Message}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(response.Result, out); err != nil {
		return fmt.Errorf("core client: decode result: %w", err)
	}
	return nil
}

func (c *Client) newRequestID() (string, error) {
	var raw [18]byte
	c.randomMu.Lock()
	_, err := io.ReadFull(c.random, raw[:])
	c.randomMu.Unlock()
	if err != nil {
		return "", err
	}
	return "req_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
