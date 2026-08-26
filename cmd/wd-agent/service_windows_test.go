//go:build windows

package main

import "testing"

func TestExtractServiceName(t *testing.T) {
	name, rest, err := extractServiceName([]string{"--service-name=CustomAgent", "--listen=", "--web-relay=https://relay.wedecent.com"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "CustomAgent" {
		t.Fatalf("name = %q", name)
	}
	if len(rest) != 2 {
		t.Fatalf("rest = %#v", rest)
	}
}

func TestBuiltInServiceAccountsRejected(t *testing.T) {
	for _, account := range []string{"LocalSystem", `NT AUTHORITY\\SYSTEM`, `NT AUTHORITY\\LocalService`, `NT AUTHORITY\\NetworkService`} {
		if !isBuiltInServiceAccount(account) {
			t.Errorf("expected %q to be rejected", account)
		}
	}
	if isBuiltInServiceAccount(`.\\WeDecentSvc`) {
		t.Fatal("dedicated local account should be accepted")
	}
}
