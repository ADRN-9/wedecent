package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeAccountService struct {
	signInStatus v1.Status
	signInErr    error
	signOutErr   error

	signInCalls  int
	signOutCalls int
	sawEmail     bool
	sawPassword  bool
}

func (f *fakeAccountService) SignIn(_ context.Context, req v1.SignInRequest) (v1.Status, error) {
	f.signInCalls++
	f.sawEmail = req.Email == "person@example.test"
	f.sawPassword = req.Password == "super-secret-password"
	return f.signInStatus, f.signInErr
}

func (f *fakeAccountService) SignOut(context.Context) error {
	f.signOutCalls++
	return f.signOutErr
}

func TestServerAccountSignInWipesParamsAndReturnsOnlyStatus(t *testing.T) {
	read := &fakeReadService{}
	accountService := &fakeAccountService{signInStatus: v1.Status{
		APIVersion: v1.Version,
		SignedIn:   true,
		UserID:     "user-123",
		Email:      "person@example.test",
		DeviceID:   "wd_aaaaaaaaaaaaaaaa",
		DeviceName: "local",
	}}
	server, err := NewServerWithAccount(read, read, accountService)
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"email":"person@example.test","password":"super-secret-password"}`)
	response := server.handle(context.Background(), Request{
		Version: v1.Version,
		ID:      "account-1",
		Method:  v1.MethodAccountSignIn,
		Params:  params,
	})
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}
	if accountService.signInCalls != 1 || !accountService.sawEmail || !accountService.sawPassword {
		t.Fatalf("unexpected sign-in dispatch state: %#v", accountService)
	}
	for i, b := range params {
		if b != 0 {
			t.Fatalf("params byte %d was not wiped", i)
		}
	}
	var status v1.Status
	if err := json.Unmarshal(response.Result, &status); err != nil {
		t.Fatal(err)
	}
	if status != accountService.signInStatus {
		t.Fatalf("status = %#v, want %#v", status, accountService.signInStatus)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "super-secret-password") {
		t.Fatalf("response leaked password: %s", encoded)
	}
}

func TestServerAccountSignInRejectsAndWipesInvalidParams(t *testing.T) {
	read := &fakeReadService{}
	accountService := &fakeAccountService{}
	server, err := NewServerWithAccount(read, read, accountService)
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"email":"person@example.test","password":"super-secret-password","extra":true}`)
	response := server.handle(context.Background(), Request{
		Version: v1.Version,
		ID:      "account-2",
		Method:  v1.MethodAccountSignIn,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorInvalidParams {
		t.Fatalf("response = %#v", response)
	}
	if accountService.signInCalls != 0 {
		t.Fatalf("sign-in calls = %d, want 0", accountService.signInCalls)
	}
	for i, b := range params {
		if b != 0 {
			t.Fatalf("params byte %d was not wiped", i)
		}
	}
}

func TestServerAccountSignInUnavailableWipesParams(t *testing.T) {
	read := &fakeReadService{}
	server, err := NewServer(read, read)
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"email":"person@example.test","password":"super-secret-password"}`)
	response := server.handle(context.Background(), Request{
		Version: v1.Version,
		ID:      "account-3",
		Method:  v1.MethodAccountSignIn,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("response = %#v", response)
	}
	for i, b := range params {
		if b != 0 {
			t.Fatalf("params byte %d was not wiped", i)
		}
	}
}

func TestServerAccountErrorsAreSanitized(t *testing.T) {
	read := &fakeReadService{}
	accountService := &fakeAccountService{
		signInErr: errors.New("account operation failed: backend included super-secret-password"),
	}
	server, err := NewServerWithAccount(read, read, accountService)
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"email":"person@example.test","password":"super-secret-password"}`)
	response := server.handle(context.Background(), Request{
		Version: v1.Version,
		ID:      "account-4",
		Method:  v1.MethodAccountSignIn,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorInternal {
		t.Fatalf("response = %#v", response)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "super-secret-password") || strings.Contains(string(encoded), "backend included") {
		t.Fatalf("response leaked account error detail: %s", encoded)
	}

	accountService.signInErr = coreapi.ErrAccountNotConfigured
	params = json.RawMessage(`{"email":"person@example.test","password":"super-secret-password"}`)
	response = server.handle(context.Background(), Request{
		Version: v1.Version,
		ID:      "account-5",
		Method:  v1.MethodAccountSignIn,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorAccountUnavailable {
		t.Fatalf("unavailable response = %#v", response)
	}

	accountService.signInErr = coreapi.ErrAccountOperation
	params = json.RawMessage(`{"email":"person@example.test","password":"super-secret-password"}`)
	response = server.handle(context.Background(), Request{
		Version: v1.Version,
		ID:      "account-6",
		Method:  v1.MethodAccountSignIn,
		Params:  params,
	})
	if response.Error == nil || response.Error.Code != ErrorAccountFailed {
		t.Fatalf("operation response = %#v", response)
	}
}

func TestServerAccountSignOutReturnsCurrentStatus(t *testing.T) {
	read := &fakeReadService{status: v1.Status{
		APIVersion: v1.Version,
		DeviceID:   "wd_aaaaaaaaaaaaaaaa",
		DeviceName: "local",
	}}
	accountService := &fakeAccountService{}
	server, err := NewServerWithAccount(read, read, accountService)
	if err != nil {
		t.Fatal(err)
	}
	response := server.handle(context.Background(), Request{
		Version: v1.Version,
		ID:      "account-7",
		Method:  v1.MethodAccountSignOut,
	})
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}
	if accountService.signOutCalls != 1 {
		t.Fatalf("sign-out calls = %d, want 1", accountService.signOutCalls)
	}
	var status v1.Status
	if err := json.Unmarshal(response.Result, &status); err != nil {
		t.Fatal(err)
	}
	if status != read.status {
		t.Fatalf("status = %#v, want %#v", status, read.status)
	}
}
