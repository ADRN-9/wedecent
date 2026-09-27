package session

// newTypedTerminalServerWithRegistry preserves the existing terminal engine but
// binds its StreamID accounting to a parent-level registry shared with other
// typed operation engines.
func newTypedTerminalServerWithRegistry(shell string, write typedTerminalFrameWriter, registry *typedParentStreamRegistry) *typedTerminalServer {
	server := newTypedTerminalServer(shell, write)
	server.states = newTypedTerminalStreamSetWithRegistry(registry)
	return server
}

func newTypedTerminalServerWithStarterAndRegistry(shell string, write typedTerminalFrameWriter, start typedTerminalStarter, registry *typedParentStreamRegistry) *typedTerminalServer {
	server := newTypedTerminalServerWithStarter(shell, write, start)
	server.states = newTypedTerminalStreamSetWithRegistry(registry)
	return server
}
