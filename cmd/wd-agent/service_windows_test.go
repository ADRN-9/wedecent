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
	for _, account := range []string{"LocalSystem", `NT AUTHORITY\SYSTEM`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`} {
		if !isBuiltInServiceAccount(account) {
			t.Errorf("expected %q to be rejected", account)
		}
	}
	if isBuiltInServiceAccount(`.\WeDecentSvc`) {
		t.Fatal("dedicated local account should be accepted")
	}
}

func TestExtractServiceNamePreservesRoutingArgs(
	t *testing.T,
) {
	args := []string{
		"--service-name=CustomAgent",
		"--route-control-listen=0.0.0.0:7444",
		"--route-control-transport=internet",
		"--route-tunnel-listen=0.0.0.0:7445",
		"--route-tunnel-transport=internet",
		"--route-max-connections=16",
	}

	name, rest, err := extractServiceName(args)
	if err != nil {
		t.Fatal(err)
	}

	if name != "CustomAgent" {
		t.Fatalf(
			"name = %q",
			name,
		)
	}

	want := args[1:]

	if len(rest) != len(want) {
		t.Fatalf(
			"rest = %#v, want %#v",
			rest,
			want,
		)
	}

	for i := range want {
		if rest[i] != want[i] {
			t.Fatalf(
				"rest[%d] = %q, want %q",
				i,
				rest[i],
				want[i],
			)
		}
	}
}
