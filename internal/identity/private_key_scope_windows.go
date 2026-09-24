//go:build windows

package identity

// Machine-scoped DPAPI is compatible with both interactive identities and the
// Windows service install flow, which provisions identity material before SCM
// starts the dedicated service account. Directory ACLs remain the local access
// boundary for the protected blob.
func defaultKeyProtectionScope() keyProtectionScope {
	return keyProtectionMachine
}
