package ipc

import (
	"context"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func (s *Server) handlePortForward(ctx context.Context, req Request, response Response) (Response, bool) {
	switch req.Method {
	case v1.MethodPortForwardStart, v1.MethodPortForwardStop, v1.MethodPortForwardList, v1.MethodPortForwardStatus:
	default:
		return Response{}, false
	}
	if s.portForwarding == nil {
		return errorResponse(response, ErrorMethodNotFound, "method not found"), true
	}

	var result any
	var err error
	switch req.Method {
	case v1.MethodPortForwardStart:
		var params v1.PortForwardStartRequest
		decodeErr := DecodeParams(req.Params, &params)
		wipe(req.Params)
		if decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		result, err = s.portForwarding.StartPortForward(ctx, params)
		params.Authorization.Signature = ""
	case v1.MethodPortForwardStop:
		var params v1.PortForwardStopRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		err = s.portForwarding.StopPortForward(ctx, params)
	case v1.MethodPortForwardStatus:
		var params v1.PortForwardStatusRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		result, err = s.portForwarding.GetPortForwardStatus(ctx, params)
	case v1.MethodPortForwardList:
		if !validEmptyParams(req.Params) {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		result, err = s.portForwarding.ListPortForwards(ctx)
	}
	return s.finish(response, result, err), true
}
