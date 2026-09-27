package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"wedecent.com/wedecent/internal/buildinfo"
	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/desktopbridge"
)

const (
	bridgeTimeout         = 3 * time.Second
	maxBridgeRequestBytes = 64 * 1024
)

var errUsage = errors.New("usage: wd-desktop-bridge <status|inventory|connect|disconnect|terminal-read|terminal-write|terminal-resize|serve|version>")

type coreSource interface {
	desktopbridge.StatusSource
	desktopbridge.InventorySource
	desktopbridge.TerminalSource
}

type idRequest struct {
	ID string `json:"id"`
}

type terminalWriteRequest struct {
	ID   string `json:"id"`
	Data []byte `json:"data"`
}

type terminalResizeRequest struct {
	ID   string `json:"id"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

type terminalStreamOpenRequest struct {
	ConnectionID string `json:"connection_id"`
	Cols         uint16 `json:"cols"`
	Rows         uint16 `json:"rows"`
	Term         string `json:"term,omitempty"`
}

type terminalStreamIDRequest struct {
	ConnectionID string `json:"connection_id"`
	TerminalID   string `json:"terminal_id"`
}

type terminalStreamWriteRequest struct {
	ConnectionID string `json:"connection_id"`
	TerminalID   string `json:"terminal_id"`
	Data         []byte `json:"data"`
}

type terminalStreamResizeRequest struct {
	ConnectionID string `json:"connection_id"`
	TerminalID   string `json:"terminal_id"`
	Cols         uint16 `json:"cols"`
	Rows         uint16 `json:"rows"`
}

type okResponse struct {
	OK bool `json:"ok"`
}

type serveEnvelope struct {
	Op      string          `json:"op"`
	Request json.RawMessage `json:"request"`
}

type serveResponse struct {
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, nil); err != nil {
		fmt.Fprintln(os.Stderr, "wd-desktop-bridge:", publicError(err))
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer, source coreSource) error {
	if len(args) != 1 {
		return errUsage
	}
	if args[0] == "version" {
		return buildinfo.Write(stdout, "wd-desktop-bridge")
	}
	if source == nil {
		client, err := coreclient.New(coreclient.Config{Timeout: bridgeTimeout})
		if err != nil {
			return err
		}
		source = client
	}
	if args[0] == "serve" {
		return serve(stdin, stdout, source)
	}

	ctx := context.Background()
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(true)
	switch args[0] {
	case "status":
		status, err := desktopbridge.GetStatus(ctx, source)
		if err != nil {
			return err
		}
		return encoder.Encode(status)
	case "inventory":
		inventory, err := desktopbridge.GetInventory(ctx, source)
		if err != nil {
			return err
		}
		return encoder.Encode(inventory)
	case "connect":
		var req idRequest
		if err := decodeRequest(stdin, &req); err != nil {
			return err
		}
		connection, err := desktopbridge.Connect(ctx, source, req.ID)
		if err != nil {
			return err
		}
		return encoder.Encode(connection)
	case "disconnect":
		var req idRequest
		if err := decodeRequest(stdin, &req); err != nil {
			return err
		}
		if err := desktopbridge.Disconnect(ctx, source, req.ID); err != nil {
			return err
		}
		return encoder.Encode(okResponse{OK: true})
	case "terminal-read":
		var req idRequest
		if err := decodeRequest(stdin, &req); err != nil {
			return err
		}
		result, err := desktopbridge.ReadTerminal(ctx, source, req.ID)
		if err != nil {
			return err
		}
		return encoder.Encode(result)
	case "terminal-write":
		var req terminalWriteRequest
		if err := decodeRequest(stdin, &req); err != nil {
			return err
		}
		if err := desktopbridge.WriteTerminal(ctx, source, req.ID, req.Data); err != nil {
			return err
		}
		return encoder.Encode(okResponse{OK: true})
	case "terminal-resize":
		var req terminalResizeRequest
		if err := decodeRequest(stdin, &req); err != nil {
			return err
		}
		if err := desktopbridge.ResizeTerminal(ctx, source, req.ID, req.Cols, req.Rows); err != nil {
			return err
		}
		return encoder.Encode(okResponse{OK: true})
	default:
		return errUsage
	}
}

func serve(stdin io.Reader, stdout io.Writer, source coreSource) error {
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 4096), maxBridgeRequestBytes)
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(true)

	for scanner.Scan() {
		result, err := handleServeRequest(scanner.Bytes(), source)
		response := serveResponse{OK: err == nil, Result: result}
		if err != nil {
			response.Result = nil
			response.Error = publicError(err)
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%w: persistent bridge input exceeds limit", desktopbridge.ErrInvalidTerminalBridgeRequest)
	}
	return nil
}

func handleServeRequest(line []byte, source coreSource) (any, error) {
	var envelope serveEnvelope
	if err := decodeRequest(bytes.NewReader(line), &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Request) == 0 {
		return nil, fmt.Errorf("%w: missing persistent bridge request", desktopbridge.ErrInvalidTerminalBridgeRequest)
	}

	ctx := context.Background()
	switch envelope.Op {
	case "connect":
		var req idRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		return desktopbridge.Connect(ctx, source, req.ID)
	case "disconnect":
		var req idRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		if err := desktopbridge.Disconnect(ctx, source, req.ID); err != nil {
			return nil, err
		}
		return okResponse{OK: true}, nil
	case "connection-latency":
		var req idRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		metrics, ok := source.(desktopbridge.LatencySource)
		if !ok {
			return nil, errors.New("connection latency is unavailable")
		}
		return desktopbridge.ProbeConnectionLatency(ctx, metrics, req.ID)
	case "terminal-read":
		var req idRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		return desktopbridge.ReadTerminal(ctx, source, req.ID)
	case "terminal-write":
		var req terminalWriteRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		if err := desktopbridge.WriteTerminal(ctx, source, req.ID, req.Data); err != nil {
			return nil, err
		}
		return okResponse{OK: true}, nil
	case "terminal-resize":
		var req terminalResizeRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		if err := desktopbridge.ResizeTerminal(ctx, source, req.ID, req.Cols, req.Rows); err != nil {
			return nil, err
		}
		return okResponse{OK: true}, nil
	case "terminal-stream-open":
		streams, ok := source.(desktopbridge.TerminalStreamSource)
		if !ok {
			return nil, errors.New("terminal streams are unavailable")
		}
		var req terminalStreamOpenRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		return desktopbridge.OpenTerminalStream(ctx, streams, req.ConnectionID, req.Cols, req.Rows, req.Term)
	case "terminal-stream-close":
		streams, ok := source.(desktopbridge.TerminalStreamSource)
		if !ok {
			return nil, errors.New("terminal streams are unavailable")
		}
		var req terminalStreamIDRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		if err := desktopbridge.CloseTerminalStream(ctx, streams, req.ConnectionID, req.TerminalID); err != nil {
			return nil, err
		}
		return okResponse{OK: true}, nil
	case "terminal-stream-read":
		streams, ok := source.(desktopbridge.TerminalStreamSource)
		if !ok {
			return nil, errors.New("terminal streams are unavailable")
		}
		var req terminalStreamIDRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		return desktopbridge.ReadTerminalStream(ctx, streams, req.ConnectionID, req.TerminalID)
	case "terminal-stream-write":
		streams, ok := source.(desktopbridge.TerminalStreamSource)
		if !ok {
			return nil, errors.New("terminal streams are unavailable")
		}
		var req terminalStreamWriteRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		if err := desktopbridge.WriteTerminalStream(ctx, streams, req.ConnectionID, req.TerminalID, req.Data); err != nil {
			return nil, err
		}
		return okResponse{OK: true}, nil
	case "terminal-stream-resize":
		streams, ok := source.(desktopbridge.TerminalStreamSource)
		if !ok {
			return nil, errors.New("terminal streams are unavailable")
		}
		var req terminalStreamResizeRequest
		if err := decodeRequest(bytes.NewReader(envelope.Request), &req); err != nil {
			return nil, err
		}
		if err := desktopbridge.ResizeTerminalStream(ctx, streams, req.ConnectionID, req.TerminalID, req.Cols, req.Rows); err != nil {
			return nil, err
		}
		return okResponse{OK: true}, nil
	default:
		return nil, fmt.Errorf("%w: unknown persistent bridge operation", desktopbridge.ErrInvalidTerminalBridgeRequest)
	}
}

func decodeRequest(reader io.Reader, out any) error {
	limited := io.LimitReader(reader, maxBridgeRequestBytes+1)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("%w: malformed bridge request", desktopbridge.ErrInvalidTerminalBridgeRequest)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: bridge request must contain one JSON value", desktopbridge.ErrInvalidTerminalBridgeRequest)
	}
	return nil
}

func publicError(err error) string {
	if errors.Is(err, errUsage) {
		return errUsage.Error()
	}
	if errors.Is(err, desktopbridge.ErrInvalidTerminalBridgeRequest) {
		return "Invalid desktop terminal request"
	}
	if coreclient.IsUnavailable(err) || errors.Is(err, context.DeadlineExceeded) {
		return "Local Core is unavailable"
	}
	var remote *coreclient.RemoteError
	if errors.As(err, &remote) {
		return "Local Core rejected the desktop request"
	}
	return "Local Core desktop request failed"
}
