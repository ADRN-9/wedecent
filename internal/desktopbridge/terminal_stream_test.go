package desktopbridge

import (
	"context"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeTerminalStreamSource struct {
	openReq   v1.TerminalStreamOpenRequest
	writeReq  v1.TerminalStreamWriteRequest
	resizeReq v1.TerminalStreamResizeRequest
	closeReq  v1.TerminalStreamCloseRequest
}

func (f *fakeTerminalStreamSource) OpenTerminalStream(_ context.Context, req v1.TerminalStreamOpenRequest) (v1.TerminalStream, error) {
	f.openReq = req
	return v1.TerminalStream{ID: "term_child", ConnectionID: req.ConnectionID}, nil
}
func (f *fakeTerminalStreamSource) CloseTerminalStream(_ context.Context, req v1.TerminalStreamCloseRequest) error {
	f.closeReq = req
	return nil
}
func (f *fakeTerminalStreamSource) ReadTerminalStream(_ context.Context, req v1.TerminalStreamReadRequest) (v1.TerminalReadResult, error) {
	return v1.TerminalReadResult{Data: []byte("child"), Closed: false}, nil
}
func (f *fakeTerminalStreamSource) WriteTerminalStream(_ context.Context, req v1.TerminalStreamWriteRequest) error {
	f.writeReq = req
	return nil
}
func (f *fakeTerminalStreamSource) ResizeTerminalStream(_ context.Context, req v1.TerminalStreamResizeRequest) error {
	f.resizeReq = req
	return nil
}

func TestTerminalStreamBridgeUsesOnlyOpaqueCoreIDs(t *testing.T) {
	source := &fakeTerminalStreamSource{}
	stream, err := OpenTerminalStream(context.Background(), source, "conn_parent", 80, 24, "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	if stream.ID != "term_child" || stream.ConnectionID != "conn_parent" {
		t.Fatalf("stream = %#v", stream)
	}
	if source.openReq.ConnectionID != "conn_parent" || source.openReq.Cols != 80 || source.openReq.Rows != 24 {
		t.Fatalf("open request = %#v", source.openReq)
	}

	if err := WriteTerminalStream(context.Background(), source, "conn_parent", "term_child", []byte("echo ok\n")); err != nil {
		t.Fatal(err)
	}
	if source.writeReq.ConnectionID != "conn_parent" || source.writeReq.TerminalID != "term_child" || string(source.writeReq.Data) != "echo ok\n" {
		t.Fatalf("write request = %#v", source.writeReq)
	}

	read, err := ReadTerminalStream(context.Background(), source, "conn_parent", "term_child")
	if err != nil {
		t.Fatal(err)
	}
	if string(read.Data) != "child" || read.Closed {
		t.Fatalf("read = %#v", read)
	}

	if err := ResizeTerminalStream(context.Background(), source, "conn_parent", "term_child", 120, 40); err != nil {
		t.Fatal(err)
	}
	if source.resizeReq.Cols != 120 || source.resizeReq.Rows != 40 {
		t.Fatalf("resize request = %#v", source.resizeReq)
	}
	if err := CloseTerminalStream(context.Background(), source, "conn_parent", "term_child"); err != nil {
		t.Fatal(err)
	}
	if source.closeReq.TerminalID != "term_child" {
		t.Fatalf("close request = %#v", source.closeReq)
	}
}

func TestTerminalStreamBridgeRejectsUnboundedInputs(t *testing.T) {
	source := &fakeTerminalStreamSource{}
	if _, err := OpenTerminalStream(context.Background(), source, "conn_parent", 0, 24, "xterm"); err == nil {
		t.Fatal("zero-width terminal was accepted")
	}
	if _, err := OpenTerminalStream(context.Background(), source, "conn_parent", 80, 24, string(make([]byte, v1.MaxTerminalTypeBytes+1))); err == nil {
		t.Fatal("oversized terminal type was accepted")
	}
	if err := WriteTerminalStream(context.Background(), source, "conn_parent", "term_child", make([]byte, v1.MaxTerminalChunkBytes+1)); err == nil {
		t.Fatal("oversized terminal write was accepted")
	}
	if err := CloseTerminalStream(context.Background(), source, "conn parent", "term_child"); err == nil {
		t.Fatal("invalid public connection ID was accepted")
	}
}
