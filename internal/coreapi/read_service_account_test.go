package coreapi

import (
	"context"
	"sync"
	"testing"

	"wedecent.com/wedecent/internal/account"
)

func TestReadServiceAccountSessionCanChangeWithoutRetainingSession(t *testing.T) {
	service := &ReadService{
		deviceID:   "wd_aaaaaaaaaaaaaaaa",
		deviceName: "local",
	}
	session := &account.Session{
		UserID:       " user-123 ",
		Email:        " person@example.test ",
		AccessToken:  "access-token-secret",
		RefreshToken: "refresh-token-secret",
	}
	if err := service.SetAccountSession(session); err != nil {
		t.Fatal(err)
	}

	session.UserID = "mutated-user"
	session.Email = "mutated@example.test"
	session.AccessToken = "mutated-access-token"

	status, err := service.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.SignedIn || status.UserID != "user-123" || status.Email != "person@example.test" {
		t.Fatalf("signed-in status = %#v", status)
	}

	if err := service.SetAccountSession(nil); err != nil {
		t.Fatal(err)
	}
	status, err = service.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.SignedIn || status.UserID != "" || status.Email != "" {
		t.Fatalf("signed-out status = %#v", status)
	}
}

func TestReadServiceAccountStateIsRaceSafe(t *testing.T) {
	service := &ReadService{
		deviceID:   "wd_aaaaaaaaaaaaaaaa",
		deviceName: "local",
	}
	session := &account.Session{UserID: "user-123", Email: "person@example.test"}

	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			if err := service.SetAccountSession(session); err != nil {
				t.Errorf("SetAccountSession: %v", err)
				return
			}
			if err := service.SetAccountSession(nil); err != nil {
				t.Errorf("SetAccountSession(nil): %v", err)
				return
			}
		}
	}()
	for i := 0; i < 4; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				status, err := service.GetStatus(context.Background())
				if err != nil {
					t.Errorf("GetStatus: %v", err)
					return
				}
				if status.SignedIn && status.UserID == "" {
					t.Errorf("signed-in status missing user ID: %#v", status)
					return
				}
				if !status.SignedIn && (status.UserID != "" || status.Email != "") {
					t.Errorf("signed-out status retained account identity: %#v", status)
					return
				}
			}
		}()
	}
	wg.Wait()
}
