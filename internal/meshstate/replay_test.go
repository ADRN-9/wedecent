package meshstate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

func TestFileRouteAuthorizationReplaySurvivesRestart(
	t *testing.T,
) {
	t.Parallel()

	path := filepath.Join(
		t.TempDir(),
		"route-authorization-replay.json",
	)
	now := time.Now().UTC().Truncate(time.Millisecond)
	expiry := now.Add(90 * time.Second)

	first, err := OpenFileRouteAuthorizationReplay(path)
	if err != nil {
		t.Fatal(err)
	}
	first.now = func() time.Time { return now }

	if err := first.ConsumeRouteAuthorization(
		context.Background(),
		"restart-safe-jti",
		expiry,
	); err != nil {
		t.Fatalf("first consume: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" &&
		info.Mode().Perm() != 0o600 {
		t.Fatalf(
			"replay-store permissions = %o, want 600",
			info.Mode().Perm(),
		)
	}

	second, err := OpenFileRouteAuthorizationReplay(path)
	if err != nil {
		t.Fatal(err)
	}
	second.now = func() time.Time { return now }

	err = second.ConsumeRouteAuthorization(
		context.Background(),
		"restart-safe-jti",
		expiry,
	)
	if !errors.Is(err, mesh.ErrRouteAuthorizationReplay) {
		t.Fatalf(
			"reopened consume error = %v, want replay",
			err,
		)
	}
}

func TestFileRouteAuthorizationReplayConsumptionIsAtomic(
	t *testing.T,
) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "replay.json")
	store, err := OpenFileRouteAuthorizationReplay(path)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }

	const attempts = 64
	var successes atomic.Int32
	var replays atomic.Int32
	var other atomic.Int32

	var wg sync.WaitGroup
	wg.Add(attempts)

	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()

			err := store.ConsumeRouteAuthorization(
				context.Background(),
				"atomic-jti",
				now.Add(time.Minute),
			)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(
				err,
				mesh.ErrRouteAuthorizationReplay,
			):
				replays.Add(1)
			default:
				other.Add(1)
			}
		}()
	}

	wg.Wait()

	if successes.Load() != 1 {
		t.Fatalf(
			"successes = %d, want 1",
			successes.Load(),
		)
	}
	if replays.Load() != attempts-1 {
		t.Fatalf(
			"replays = %d, want %d",
			replays.Load(),
			attempts-1,
		)
	}
	if other.Load() != 0 {
		t.Fatalf(
			"unexpected errors = %d",
			other.Load(),
		)
	}
}

func TestFileRouteAuthorizationReplayPrunesExpiredState(
	t *testing.T,
) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "replay.json")
	store, err := OpenFileRouteAuthorizationReplay(path)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }

	if err := store.ConsumeRouteAuthorization(
		context.Background(),
		"old-jti",
		now.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}

	later := now.Add(2 * time.Second)
	store.now = func() time.Time { return later }

	if err := store.ConsumeRouteAuthorization(
		context.Background(),
		"new-jti",
		later.Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileRouteAuthorizationReplay(path)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return later }

	// old-jti expired and was removed from durable state, so the replay
	// adapter itself permits reuse. A real expired signed capability is still
	// rejected earlier by RouteAuthorizationVerifier.
	if err := reopened.ConsumeRouteAuthorization(
		context.Background(),
		"old-jti",
		later.Add(time.Minute),
	); err != nil {
		t.Fatalf(
			"expired replay entry was not pruned: %v",
			err,
		)
	}
}

func TestFileRouteAuthorizationReplayWriteFailureDoesNotBurnJTI(
	t *testing.T,
) {
	t.Parallel()

	root := t.TempDir()
	parent := filepath.Join(root, "state")
	path := filepath.Join(parent, "replay.json")

	store, err := OpenFileRouteAuthorizationReplay(path)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }

	// Block MkdirAll by placing a regular file where the state directory
	// needs to be.
	if err := os.WriteFile(parent, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = store.ConsumeRouteAuthorization(
		context.Background(),
		"retry-after-write-failure",
		now.Add(time.Minute),
	)
	if err == nil {
		t.Fatal("consume unexpectedly succeeded with unwritable state")
	}

	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	// The failed durable write must not have consumed the JTI in memory.
	if err := store.ConsumeRouteAuthorization(
		context.Background(),
		"retry-after-write-failure",
		now.Add(time.Minute),
	); err != nil {
		t.Fatalf(
			"JTI burned by failed persistence: %v",
			err,
		)
	}
}

func TestOpenFileRouteAuthorizationReplayRejectsSymlink(
	t *testing.T,
) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink availability varies on Windows")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")

	if err := os.WriteFile(
		target,
		[]byte(`{"version":1,"used":{}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "replay.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := OpenFileRouteAuthorizationReplay(link); !errors.Is(
		err,
		ErrRouteReplayStoreInvalid,
	) {
		t.Fatalf(
			"OpenFileRouteAuthorizationReplay() error = %v, want invalid store",
			err,
		)
	}
}

func TestOpenFileRouteAuthorizationReplayRejectsMalformedState(
	t *testing.T,
) {
	t.Parallel()

	cases := []string{
		`{`,
		`{"version":2,"used":{}}`,
		`{"version":1,"used":{"":123}}`,
		`{"version":1,"used":{"jti":0}}`,
		`{"version":1,"used":{},"extra":true}`,
		`{"version":1,"used":{}} {"version":1,"used":{}}`,
	}

	for i, content := range cases {
		i, content := i, content
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(
				t.TempDir(),
				"replay.json",
			)
			if err := os.WriteFile(
				path,
				[]byte(content),
				0o600,
			); err != nil {
				t.Fatal(err)
			}

			if _, err := OpenFileRouteAuthorizationReplay(path); !errors.Is(
				err,
				ErrRouteReplayStoreInvalid,
			) {
				t.Fatalf(
					"error = %v, want invalid store",
					err,
				)
			}
		})
	}
}

func TestFileRouteAuthorizationReplayHonorsCanceledContext(
	t *testing.T,
) {
	t.Parallel()

	store, err := OpenFileRouteAuthorizationReplay(
		filepath.Join(t.TempDir(), "replay.json"),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = store.ConsumeRouteAuthorization(
		ctx,
		"canceled-jti",
		time.Now().Add(time.Minute),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"consume error = %v, want context.Canceled",
			err,
		)
	}
}
