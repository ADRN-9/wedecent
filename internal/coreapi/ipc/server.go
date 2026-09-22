package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const (
	ErrorInvalidParams         = "invalid_params"
	ErrorMethodNotFound        = "method_not_found"
	ErrorDeviceNotFound        = "device_not_found"
	ErrorRouteNotFound         = "route_not_found"
	ErrorConnectionNotFound    = "connection_not_found"
	ErrorConnectionLimit       = "connection_limit"
	ErrorConnectionUnavailable = "connection_unavailable"
	ErrorConnectionFailed      = "connection_failed"
	ErrorRequestCanceled       = "request_canceled"
	ErrorAccountUnavailable    = "account_unavailable"
	ErrorAccountFailed         = "account_operation_failed"
	ErrorInternal              = "internal_error"
)

type Services struct {
	Status      v1.StatusService
	Devices     v1.DeviceService
	Account     v1.AccountService
	Connections v1.ConnectionService
	Transports  v1.TransportService
	Routes      v1.RouteService
}

type Server struct {
	status      v1.StatusService
	devices     v1.DeviceService
	account     v1.AccountService
	connections v1.ConnectionService
	transports  v1.TransportService
	routes      v1.RouteService
}

func NewServer(status v1.StatusService, devices v1.DeviceService) (*Server, error) {
	return NewServerWithServices(Services{Status: status, Devices: devices})
}

func NewServerWithAccount(status v1.StatusService, devices v1.DeviceService, accountService v1.AccountService) (*Server, error) {
	return NewServerWithServices(Services{Status: status, Devices: devices, Account: accountService})
}

func NewServerWithServices(services Services) (*Server, error) {
	if services.Status == nil || services.Devices == nil {
		return nil, errors.New("coreapi ipc: status and device services are required")
	}
	return &Server{
		status:      services.Status,
		devices:     services.Devices,
		account:     services.Account,
		connections: services.Connections,
		transports:  services.Transports,
		routes:      services.Routes,
	}, nil
}

// ServeOne handles exactly one framed request and writes exactly one framed
// response. It deliberately does not listen on a socket; the platform local IPC
// adapter provides the same-user boundary.
func (s *Server) ServeOne(ctx context.Context, rw io.ReadWriter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if rw == nil {
		return errors.New("coreapi ipc: connection is required")
	}

	req, err := ReadRequest(rw)
	if err != nil {
		return err
	}
	response := s.handle(ctx, req)
	if err := WriteResponse(rw, response); err != nil {
		if !errors.Is(err, ErrFrameTooLarge) {
			return err
		}
		fallback := errorResponse(
			Response{Version: v1.Version, ID: req.ID},
			ErrorInternal,
			"internal error",
		)
		return WriteResponse(rw, fallback)
	}
	return nil
}

func (s *Server) handle(ctx context.Context, req Request) Response {
	response := Response{Version: v1.Version, ID: req.ID}
	var result any
	var err error

	switch req.Method {
	case v1.MethodStatusGet:
		if !validEmptyParams(req.Params) {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		}
		result, err = s.status.GetStatus(ctx)
	case v1.MethodAccountSignIn:
		if s.account == nil {
			wipe(req.Params)
			return errorResponse(response, ErrorMethodNotFound, "method not found")
		}
		var params v1.SignInRequest
		decodeErr := DecodeParams(req.Params, &params)
		wipe(req.Params)
		if decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		}
		result, err = s.account.SignIn(ctx, params)
		params.Password = ""
	case v1.MethodAccountSignOut:
		if s.account == nil {
			return errorResponse(response, ErrorMethodNotFound, "method not found")
		}
		if !validEmptyParams(req.Params) {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		}
		err = s.account.SignOut(ctx)
		if err == nil {
			result, err = s.status.GetStatus(ctx)
		}
	case v1.MethodDevicesList:
		if !validEmptyParams(req.Params) {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		}
		result, err = s.devices.ListDevices(ctx)
	case v1.MethodDeviceGet:
		var params v1.GetDeviceRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		}
		result, err = s.devices.GetDevice(ctx, params)
	case v1.MethodConnectionConnect:
		if s.connections == nil {
			return errorResponse(response, ErrorMethodNotFound, "method not found")
		}
		var params v1.ConnectRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		}
		result, err = s.connections.Connect(ctx, params)
	case v1.MethodConnectionDisconnect:
		if s.connections == nil {
			return errorResponse(response, ErrorMethodNotFound, "method not found")
		}
		var params v1.DisconnectRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		}
		err = s.connections.Disconnect(ctx, params)
	case v1.MethodTransportsList:
		if s.transports == nil {
			return errorResponse(response, ErrorMethodNotFound, "method not found")
		}
		if !validEmptyParams(req.Params) {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		}
		result, err = s.transports.GetTransportStatus(ctx)
	case v1.MethodRouteGet:
		if s.routes == nil {
			return errorResponse(response, ErrorMethodNotFound, "method not found")
		}
		var params v1.GetRouteStatusRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		}
		result, err = s.routes.GetRouteStatus(ctx, params)
	default:
		return errorResponse(response, ErrorMethodNotFound, "method not found")
	}

	if err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return errorResponse(response, ErrorRequestCanceled, "request canceled")
		case errors.Is(err, coreapi.ErrDeviceNotFound):
			return errorResponse(response, ErrorDeviceNotFound, "device not found")
		case errors.Is(err, coreapi.ErrInvalidRouteRequest), errors.Is(err, coreapi.ErrInvalidConnectionRequest):
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters")
		case errors.Is(err, coreapi.ErrRouteNotFound):
			return errorResponse(response, ErrorRouteNotFound, "route not found")
		case errors.Is(err, coreapi.ErrConnectionNotFound):
			return errorResponse(response, ErrorConnectionNotFound, "connection not found")
		case errors.Is(err, coreapi.ErrConnectionLimit):
			return errorResponse(response, ErrorConnectionLimit, "connection limit reached")
		case errors.Is(err, coreapi.ErrConnectionServiceClosed):
			return errorResponse(response, ErrorConnectionUnavailable, "connection service is unavailable")
		case errors.Is(err, coreapi.ErrConnectionOperation):
			return errorResponse(response, ErrorConnectionFailed, "connection operation failed")
		case errors.Is(err, coreapi.ErrAccountNotConfigured):
			return errorResponse(response, ErrorAccountUnavailable, "account sign-in is unavailable")
		case errors.Is(err, coreapi.ErrAccountOperation):
			return errorResponse(response, ErrorAccountFailed, "account operation failed")
		default:
			return errorResponse(response, ErrorInternal, "internal error")
		}
	}

	encoded, err := MarshalResult(result)
	if err != nil {
		return errorResponse(response, ErrorInternal, "internal error")
	}
	response.Result = encoded
	return response
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func errorResponse(response Response, code, message string) Response {
	response.Result = nil
	response.Error = &ResponseError{Code: code, Message: message}
	return response
}

func validEmptyParams(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var empty struct{}
	return decodeStrict(raw, &empty) == nil
}
