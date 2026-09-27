package session

import (
	"context"
	"errors"
	"testing"
)

type testFileTransferAuthorizer struct {
	request FileTransferAuthorizationRequest
	err     error
}

func (a *testFileTransferAuthorizer) AuthorizeFileTransfer(_ context.Context, req FileTransferAuthorizationRequest) error {
	a.request = req
	return a.err
}

func TestStaticFileTransferAuthorizerIsDirectionSpecificAndDenyByDefault(t *testing.T) {
	ctx := context.Background()
	peer := "wd_peer1234567890"

	for _, direction := range []FileTransferDirection{FileTransferUpload, FileTransferDownload} {
		if err := (StaticFileTransferAuthorizer{}).AuthorizeFileTransfer(ctx, FileTransferAuthorizationRequest{
			PeerID: peer, Direction: direction, Path: "safe/file",
		}); err == nil {
			t.Fatalf("default policy authorized %s", direction)
		}
	}

	uploadOnly := StaticFileTransferAuthorizer{AllowUpload: true}
	if err := uploadOnly.AuthorizeFileTransfer(ctx, FileTransferAuthorizationRequest{PeerID: peer, Direction: FileTransferUpload, Path: "safe/file"}); err != nil {
		t.Fatal(err)
	}
	if err := uploadOnly.AuthorizeFileTransfer(ctx, FileTransferAuthorizationRequest{PeerID: peer, Direction: FileTransferDownload, Path: "safe/file"}); err == nil {
		t.Fatal("upload-only policy authorized download")
	}

	downloadOnly := StaticFileTransferAuthorizer{AllowDownload: true}
	if err := downloadOnly.AuthorizeFileTransfer(ctx, FileTransferAuthorizationRequest{PeerID: peer, Direction: FileTransferDownload, Path: "safe/file"}); err != nil {
		t.Fatal(err)
	}
	if err := downloadOnly.AuthorizeFileTransfer(ctx, FileTransferAuthorizationRequest{PeerID: peer, Direction: FileTransferUpload, Path: "safe/file"}); err == nil {
		t.Fatal("download-only policy authorized upload")
	}
}

func TestStaticFileTransferAuthorizerRequiresAuthenticatedPeerAndCanonicalPath(t *testing.T) {
	authorizer := StaticFileTransferAuthorizer{AllowUpload: true, AllowDownload: true}
	if err := authorizer.AuthorizeFileTransfer(context.Background(), FileTransferAuthorizationRequest{
		Direction: FileTransferUpload, Path: "safe/file",
	}); err == nil {
		t.Fatal("authorized operation without authenticated peer")
	}
	if err := authorizer.AuthorizeFileTransfer(context.Background(), FileTransferAuthorizationRequest{
		PeerID: "wd_peer", Direction: FileTransferDownload, Path: "../escape",
	}); err == nil {
		t.Fatal("authorized non-canonical path")
	}
	if err := authorizer.AuthorizeFileTransfer(context.Background(), FileTransferAuthorizationRequest{
		PeerID: "wd_peer", Direction: "unknown", Path: "safe/file",
	}); err == nil {
		t.Fatal("authorized unknown direction")
	}
}

func TestFileTransferRuntimeRequiresStoreAndIndependentAuthorizer(t *testing.T) {
	if (&FileTransferRuntime{}).Ready() {
		t.Fatal("empty file transfer runtime reported ready")
	}

	store, err := OpenFileTransferStore(t.TempDir(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if (&FileTransferRuntime{Store: store}).Ready() {
		t.Fatal("runtime without file authorizer reported ready")
	}

	authorizer := &testFileTransferAuthorizer{}
	runtime := &FileTransferRuntime{Store: store, Authorizer: authorizer}
	if !runtime.Ready() {
		t.Fatal("complete file transfer runtime did not report ready")
	}
	if err := runtime.Authorize(context.Background(), "wd_peer", FileTransferDownload, "docs/file"); err != nil {
		t.Fatal(err)
	}
	if authorizer.request.PeerID != "wd_peer" || authorizer.request.Direction != FileTransferDownload || authorizer.request.Path != "docs/file" {
		t.Fatalf("authorization request = %#v", authorizer.request)
	}
}

func TestFileTransferRuntimePropagatesCancellationAndDenial(t *testing.T) {
	store, err := OpenFileTransferStore(t.TempDir(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	denied := errors.New("denied for test")
	runtime := &FileTransferRuntime{Store: store, Authorizer: &testFileTransferAuthorizer{err: denied}}
	if err := runtime.Authorize(context.Background(), "wd_peer", FileTransferUpload, "safe/file"); !errors.Is(err, denied) {
		t.Fatalf("denial = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	static := &FileTransferRuntime{Store: store, Authorizer: StaticFileTransferAuthorizer{AllowUpload: true}}
	if err := static.Authorize(ctx, "wd_peer", FileTransferUpload, "safe/file"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
}
