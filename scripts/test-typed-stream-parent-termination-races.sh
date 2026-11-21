#!/usr/bin/env bash
set -euo pipefail
set -x
go test -race ./internal/session -run '^(TestDispatchTypedSessionFrameRejectsBufferedOpenAfterRevocation|TestTypedTerminalServerRejectsBufferedOpenAfterParentCleanup|TestTypedTerminalServerParentCleanupWaitsForInFlightStreamOpen|TestTypedHandlerRevocationWaitsForInFlightStreamOpenCleanupFailure)$' -count=20
