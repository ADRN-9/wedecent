package scmbroker

// withImpersonation guarantees that authorization is denied if reversion fails.
func withImpersonation(impersonate, revert func() error, authorize func() (bool, error)) (authorized bool, err error) {
	// Windows impersonation is thread-scoped; keep the goroutine on this OS thread
	// until RevertToSelf has completed.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := impersonate(); err != nil {
		return false, err
	}
	defer func() {
		if revertErr := revert(); revertErr != nil {
			authorized = false
			err = revertErr
		}
	}()
	return authorize()
}
