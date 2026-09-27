package ipc

import (
	"context"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func (s *Server) handleTerminalStream(ctx context.Context, req Request, response Response) (Response, bool) {
	if req.Method != v1.MethodTerminalStreamOpen &&
		req.Method != v1.MethodTerminalStreamClose &&
		req.Method != v1.MethodTerminalStreamRead &&
		req.Method != v1.MethodTerminalStreamWrite &&
		req.Method != v1.MethodTerminalStreamResize {
		return Response{}, false
	}

	streams, ok := s.terminal.(v1.TerminalStreamService)
	if !ok {
		return errorResponse(response, ErrorMethodNotFound, "method not found"), true
	}

	var result any
	var err error
	switch req.Method {
	case v1.MethodTerminalStreamOpen:
		var params v1.TerminalStreamOpenRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		result, err = streams.OpenTerminalStream(ctx, params)
	case v1.MethodTerminalStreamClose:
		var params v1.TerminalStreamCloseRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		err = streams.CloseTerminalStream(ctx, params)
	case v1.MethodTerminalStreamRead:
		var params v1.TerminalStreamReadRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		result, err = streams.ReadTerminalStream(ctx, params)
	case v1.MethodTerminalStreamWrite:
		var params v1.TerminalStreamWriteRequest
		decodeErr := DecodeParams(req.Params, &params)
		wipe(req.Params)
		if decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		err = streams.WriteTerminalStream(ctx, params)
		wipe(params.Data)
	case v1.MethodTerminalStreamResize:
		var params v1.TerminalStreamResizeRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		err = streams.ResizeTerminalStream(ctx, params)
	}
	return s.finish(response, result, err), true
}
