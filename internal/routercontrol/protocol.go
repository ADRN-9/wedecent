package routercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"wedecent.com/wedecent/internal/coreapi"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const controlIOTimeout = 10 * time.Second

// DialFunc opens one already-authenticated local router-control stream.
// Implementations must not return general network connections to untrusted
// peers; Client treats the returned stream as an administrative authority.
type DialFunc func(context.Context) (net.Conn, error)

// ProtocolServer serves only the narrow router administration contract. It does
// not expose account, device, terminal, route-authorization, or trust methods.
type ProtocolServer struct {
	Service v1.RouterService
}

// ServeOne handles exactly one framed router-control request.
func (s *ProtocolServer) ServeOne(ctx context.Context, rw io.ReadWriter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.Service == nil || rw == nil {
		return coreapi.ErrRouterUnavailable
	}

	req, err := ipc.ReadRequest(rw)
	if err != nil {
		return err
	}

	response := ipc.Response{Version: v1.Version, ID: req.ID}
	var result any

	switch req.Method {
	case v1.MethodRouterPolicyGet:
		if err := decodeEmptyParams(req.Params); err != nil {
			response.Error = protocolError(ipc.ErrorInvalidParams, "invalid request parameters")
			return ipc.WriteResponse(rw, response)
		}
		result, err = s.Service.GetRouterPolicy(ctx)
	case v1.MethodRouterPolicySet:
		var params v1.SetRouterPolicyRequest
		if decodeErr := ipc.DecodeParams(req.Params, &params); decodeErr != nil {
			response.Error = protocolError(ipc.ErrorInvalidParams, "invalid request parameters")
			return ipc.WriteResponse(rw, response)
		}
		result, err = s.Service.SetRouterPolicy(ctx, params)
	case v1.MethodRouterStatsGet:
		if err := decodeEmptyParams(req.Params); err != nil {
			response.Error = protocolError(ipc.ErrorInvalidParams, "invalid request parameters")
			return ipc.WriteResponse(rw, response)
		}
		result, err = s.Service.GetRouterStats(ctx)
	default:
		response.Error = protocolError(ipc.ErrorMethodNotFound, "method not found")
		return ipc.WriteResponse(rw, response)
	}

	if err != nil {
		response.Error = routerServiceProtocolError(err)
		return ipc.WriteResponse(rw, response)
	}

	response.Result, err = ipc.MarshalResult(result)
	if err != nil {
		response.Error = protocolError(ipc.ErrorInternal, "internal error")
	}
	return ipc.WriteResponse(rw, response)
}

// Client implements v1.RouterService by issuing one bounded request over one
// authenticated local stream per operation.
type Client struct {
	Dial DialFunc
	next atomic.Uint64
}

var _ v1.RouterService = (*Client)(nil)

func (c *Client) GetRouterPolicy(ctx context.Context) (v1.RouterPolicy, error) {
	var policy v1.RouterPolicy
	if err := c.call(ctx, v1.MethodRouterPolicyGet, nil, &policy); err != nil {
		return v1.RouterPolicy{}, err
	}
	return policy, nil
}

func (c *Client) SetRouterPolicy(
	ctx context.Context,
	req v1.SetRouterPolicyRequest,
) (v1.RouterPolicy, error) {
	var policy v1.RouterPolicy
	if err := c.call(ctx, v1.MethodRouterPolicySet, req, &policy); err != nil {
		return v1.RouterPolicy{}, err
	}
	return policy, nil
}

func (c *Client) GetRouterStats(ctx context.Context) (v1.RouterStats, error) {
	var stats v1.RouterStats
	if err := c.call(ctx, v1.MethodRouterStatsGet, nil, &stats); err != nil {
		return v1.RouterStats{}, err
	}
	return stats, nil
}

func (c *Client) call(ctx context.Context, method string, params any, result any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || c.Dial == nil {
		return coreapi.ErrRouterUnavailable
	}

	requestCtx, cancel := context.WithTimeout(ctx, controlIOTimeout)
	defer cancel()

	conn, err := c.Dial(requestCtx)
	if err != nil {
		if ctxErr := requestCtx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: open control channel", coreapi.ErrRouterUnavailable)
	}
	if conn == nil {
		return coreapi.ErrRouterUnavailable
	}
	defer conn.Close()

	deadline, _ := requestCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(requestCtx, func() {
		defer close(closeDone)
		_ = conn.Close()
	})
	defer func() {
		if !stopClose() {
			<-closeDone
		}
	}()

	var rawParams json.RawMessage
	if params != nil {
		rawParams, err = ipc.MarshalResult(params)
		if err != nil {
			return fmt.Errorf("%w: encode request", coreapi.ErrRouterOperation)
		}
	}

	requestID := fmt.Sprintf("router-%d", c.next.Add(1))
	req := ipc.Request{
		Version: v1.Version,
		ID:      requestID,
		Method:  method,
		Params:  rawParams,
	}
	if err := ipc.WriteRequest(conn, req); err != nil {
		if ctxErr := requestCtx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: write control request", coreapi.ErrRouterOperation)
	}

	response, err := ipc.ReadResponse(conn)
	if err != nil {
		if ctxErr := requestCtx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: read control response", coreapi.ErrRouterOperation)
	}
	if response.ID != requestID {
		return fmt.Errorf("%w: mismatched response id", coreapi.ErrRouterOperation)
	}
	if response.Error != nil {
		return protocolResponseError(response.Error)
	}
	if result == nil {
		return nil
	}
	if err := ipc.DecodeParams(response.Result, result); err != nil {
		return fmt.Errorf("%w: decode control result", coreapi.ErrRouterOperation)
	}
	return nil
}

func decodeEmptyParams(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var empty struct{}
	return ipc.DecodeParams(raw, &empty)
}

func routerServiceProtocolError(err error) *ipc.ResponseError {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return protocolError(ipc.ErrorRequestCanceled, "request canceled")
	case errors.Is(err, coreapi.ErrInvalidRouterPolicy):
		return protocolError(ipc.ErrorInvalidParams, "invalid request parameters")
	case errors.Is(err, coreapi.ErrRouterUnavailable):
		return protocolError(ipc.ErrorRouterUnavailable, "router service is unavailable")
	case errors.Is(err, coreapi.ErrRouterOperation):
		return protocolError(ipc.ErrorRouterFailed, "router operation failed")
	default:
		return protocolError(ipc.ErrorInternal, "internal error")
	}
}

func protocolResponseError(responseErr *ipc.ResponseError) error {
	if responseErr == nil {
		return nil
	}
	switch responseErr.Code {
	case ipc.ErrorInvalidParams:
		return coreapi.ErrInvalidRouterPolicy
	case ipc.ErrorRouterUnavailable:
		return coreapi.ErrRouterUnavailable
	case ipc.ErrorRequestCanceled:
		return context.Canceled
	case ipc.ErrorRouterFailed, ipc.ErrorInternal, ipc.ErrorMethodNotFound:
		return coreapi.ErrRouterOperation
	default:
		return coreapi.ErrRouterOperation
	}
}

func protocolError(code, message string) *ipc.ResponseError {
	return &ipc.ResponseError{Code: code, Message: message}
}
