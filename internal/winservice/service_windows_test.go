//go:build windows

package winservice

import ("strings"; "testing")

func TestStateName(t *testing.T) {
	cases := map[uint32]string{
		serviceStopped:      "stopped",
		serviceStartPending: "start-pending",
		serviceStopPending:  "stop-pending",
		serviceRunning:      "running",
	}
	for state, want := range cases {
		if got := stateName(state); got != want {
			t.Fatalf("stateName(%d) = %q, want %q", state, got, want)
		}
	}
}

func TestServiceControlSecurityDescriptorIsLeastPrivilege(t *testing.T) {
	got := serviceControlSecurityDescriptor()
	want := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000004;;;AU)"
	if got != want {
		t.Fatalf("service DACL = %q, want %q", got, want)
	}
	if strings.Contains(got, "WD") || strings.Contains(got, "WO") {
		t.Fatalf("service DACL must not grant write-DACL or write-owner to ordinary callers: %q", got)
	}
}

func TestServiceManagementUsesLeastPrivilegeMasks(t *testing.T) {
	if scManagerConnect != 0x1 || scManagerCreateService != 0x2 {
		t.Fatalf("unexpected SCM manager access masks: connect=%#x create=%#x", scManagerConnect, scManagerCreateService)
	}
	if serviceQueryStatus != 0x4 || serviceStart != 0x10 || serviceStop != 0x20 || serviceDelete != 0x10000 || serviceWriteDACL != 0x40000 {
		t.Fatalf("unexpected service access masks")
	}
	if serviceStart&serviceAllAccess == 0 || serviceStop&serviceAllAccess == 0 {
		t.Fatal("service operation masks are not represented in SERVICE_ALL_ACCESS")
	}
}
