//go:build windows

package updateinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func readProtectedInstalledVersion() (string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return "", errors.New("ProgramData is unavailable")
	}
	path := filepath.Join(programData, "WeDecent", "installer.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("protected installer metadata is unavailable")
	}
	name, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.New("installer metadata traverses a reparse point")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return "", errors.New("installer metadata security descriptor is unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "", errors.New("installer metadata owner is unavailable")
	}
	if owner.String() != updateStateSystemSID && owner.String() != updateStateAdminSID {
		return "", errors.New("installer metadata owner is not SYSTEM or Administrators")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return "", errors.New("installer metadata requires a non-null DACL")
	}
	sddl := sd.String()
	start := strings.Index(sddl, "D:")
	if start < 0 || !strings.HasPrefix(sddl[start+2:], "P") {
		return "", errors.New("installer metadata DACL must be protected")
	}
	entries := sddl[start+3:]
	if end := strings.Index(entries, "S:"); end >= 0 {
		entries = entries[:end]
	}
	grants := map[string]bool{}
	for len(entries) > 0 {
		if entries[0] != '(' {
			return "", errors.New("installer metadata DACL is malformed")
		}
		end := strings.IndexByte(entries[1:], ')')
		if end < 0 {
			return "", errors.New("installer metadata DACL has unterminated ACE")
		}
		end++
		parts := strings.Split(entries[1:end], ";")
		if len(parts) != 6 || parts[0] != "A" || parts[1] != "" || parts[3] != "" || parts[4] != "" {
			return "", errors.New("installer metadata DACL contains unsupported ACE")
		}
		mask, err := parseUpdateStateAccessMask(parts[2])
		if err != nil || mask != 0x001F01FF {
			return "", errors.New("installer metadata DACL must grant only full control")
		}
		if parts[5] != updateStateSystemSID && parts[5] != updateStateAdminSID {
			return "", errors.New("installer metadata DACL grants an untrusted principal")
		}
		grants[parts[5]] = true
		entries = entries[end+1:]
	}
	if !grants[updateStateSystemSID] || !grants[updateStateAdminSID] {
		return "", errors.New("installer metadata DACL must grant SYSTEM and Administrators")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var metadata struct {
		Schema     int    `json:"schema"`
		Product    string `json:"product"`
		Version    string `json:"version"`
		InstallDir string `json:"install_dir"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return "", fmt.Errorf("decode protected installer metadata: %w", err)
	}
	if metadata.Schema != 1 || metadata.Product != "WeDecent" || metadata.InstallDir == "" {
		return "", errors.New("protected installer metadata has invalid identity")
	}
	if _, err := parseStableVersion(metadata.Version); err != nil {
		return "", errors.New("protected installed version is invalid")
	}
	installDir, err := filepath.Abs(metadata.InstallDir)
	if err != nil {
		return "", errors.New("protected install directory is invalid")
	}
	installInfo, err := os.Lstat(installDir)
	if err != nil || !installInfo.IsDir() || installInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("protected installation directory is unavailable")
	}
	agent := filepath.Join(installDir, "wd-agent.exe")
	agentInfo, err := os.Lstat(agent)
	if err != nil || !agentInfo.Mode().IsRegular() || agentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("installed agent binary is unavailable")
	}
	return metadata.Version, nil
}
