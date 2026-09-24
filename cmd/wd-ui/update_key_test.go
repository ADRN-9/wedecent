package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunUpdateKeyCommandReportsUnprovisionedByDefault(t *testing.T) {
	var output bytes.Buffer
	if err := runUpdateKeyCommand([]string{"status"}, &output); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "provisioned=false\n" {
		t.Fatalf("status output = %q", got)
	}
}

func TestRunUpdateKeyCommandUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"status", "extra"}, {"enable"}} {
		if err := runUpdateKeyCommand(args, &strings.Builder{}); !errors.Is(err, ErrUpdateKeyUsage) {
			t.Fatalf("args %q error = %v", args, err)
		}
	}
}
