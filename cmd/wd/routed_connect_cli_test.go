package main

import (
	"strings"
	"testing"
)

func TestRunConnectRejectsRoutedWithDestinationOverride(t *testing.T) {
	_, err := runConnect([]string{
		"--state", t.TempDir(),
		"--route-router", "wd_bbbbbbbbbbbbbbbb",
		"--route-first-transport", "lan",
		"--route-second-transport", "lan",
		"--endpoint", "127.0.0.1:7443",
		"wd_cccccccccccccccc",
	})
	if err == nil || !strings.Contains(err.Error(), "routed connections cannot be combined") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunConnectRejectsPartialRoutedConfiguration(t *testing.T) {
	_, err := runConnect([]string{
		"--state", t.TempDir(),
		"--route-router", "wd_bbbbbbbbbbbbbbbb",
		"wd_cccccccccccccccc",
	})
	if err == nil || !strings.Contains(err.Error(), "both hop transports") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunConnectUsageMentionsRouting(t *testing.T) {
	_, err := runConnect(nil)
	if err == nil || !strings.Contains(err.Error(), "--route-router") {
		t.Fatalf("error = %v", err)
	}
}
