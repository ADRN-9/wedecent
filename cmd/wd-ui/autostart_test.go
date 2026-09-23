package main

import (
	"bytes"
	"errors"
	"testing"
)

type memoryAutostartStore struct {
	value   string
	present bool
	setErr  error
	getErr  error
	delErr  error
}

func (s *memoryAutostartStore) Get() (string, bool, error) {
	return s.value, s.present, s.getErr
}

func (s *memoryAutostartStore) Set(value string) error {
	if s.setErr != nil {
		return s.setErr
	}
	s.value = value
	s.present = true
	return nil
}

func (s *memoryAutostartStore) Delete() error {
	if s.delErr != nil {
		return s.delErr
	}
	s.value = ""
	s.present = false
	return nil
}

func TestEnableAutostartStoresOnlyQuotedExecutable(t *testing.T) {
	store := &memoryAutostartStore{}
	path := `C:\Program Files\WeDecent\wd-ui.exe`
	if err := enableAutostartWith(store, func() (string, error) { return path, nil }); err != nil {
		t.Fatal(err)
	}
	want := `"C:\Program Files\WeDecent\wd-ui.exe"`
	if store.value != want || !store.present {
		t.Fatalf("stored value = %q, present=%v; want %q, true", store.value, store.present, want)
	}
}

func TestAutostartStatusDistinguishesDisabledEnabledAndStale(t *testing.T) {
	path := `C:\Program Files\WeDecent\wd-ui.exe`
	executable := func() (string, error) { return path, nil }
	store := &memoryAutostartStore{}

	status, err := autostartStatusWith(store, executable)
	if err != nil || status != autostartStatusDisabled {
		t.Fatalf("disabled status = %q, %v", status, err)
	}
	store.value = `"C:\Program Files\WeDecent\wd-ui.exe"`
	store.present = true
	status, err = autostartStatusWith(store, executable)
	if err != nil || status != autostartStatusEnabled {
		t.Fatalf("enabled status = %q, %v", status, err)
	}
	store.value = `"C:\Old\wd-ui.exe"`
	status, err = autostartStatusWith(store, executable)
	if err != nil || status != autostartStatusStale {
		t.Fatalf("stale status = %q, %v", status, err)
	}
}

func TestDisabledAutostartStatusDoesNotNeedExecutablePath(t *testing.T) {
	store := &memoryAutostartStore{}
	calls := 0
	status, err := autostartStatusWith(store, func() (string, error) {
		calls++
		return "", ErrAutostartExecutable
	})
	if err != nil || status != autostartStatusDisabled {
		t.Fatalf("status = %q, %v", status, err)
	}
	if calls != 0 {
		t.Fatalf("executable resolver calls = %d; want 0", calls)
	}
}

func TestDisableAutostartIsStoreDrivenAndIdempotent(t *testing.T) {
	store := &memoryAutostartStore{value: `"C:\Program Files\WeDecent\wd-ui.exe"`, present: true}
	if err := disableAutostartWith(store); err != nil {
		t.Fatal(err)
	}
	if store.present {
		t.Fatal("autostart value still present")
	}
	if err := disableAutostartWith(store); err != nil {
		t.Fatalf("second disable: %v", err)
	}
}

func TestAutostartCommandLineRejectsUnsafeExecutableText(t *testing.T) {
	for _, value := range []string{"", "   ", "bad\npath", "bad\rpath", "bad\x00path", `C:\bad"path\wd-ui.exe`} {
		if _, err := autostartCommandLine(value); !errors.Is(err, ErrAutostartExecutable) {
			t.Fatalf("autostartCommandLine(%q) error = %v; want ErrAutostartExecutable", value, err)
		}
	}
}

func TestAutostartCommandRejectsInvalidArgumentsBeforePlatformMutation(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"bogus"}, {"enable", "extra"}} {
		var out bytes.Buffer
		if err := runAutostartCommand(args, &out); !errors.Is(err, ErrAutostartUsage) {
			t.Fatalf("args %#v error = %v; want ErrAutostartUsage", args, err)
		}
		if out.Len() != 0 {
			t.Fatalf("args %#v wrote output %q", args, out.String())
		}
	}
}
