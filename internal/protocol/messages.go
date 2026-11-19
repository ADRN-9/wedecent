package protocol

import "encoding/json"

type PairRequest struct {
	PairingSecret string `json:"pairing_secret"`
	ClientID      string `json:"client_id"`
	ClientName    string `json:"client_name"`
}

type PairResponse struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
}

type OpenSession struct {
	Cols         uint16       `json:"cols"`
	Rows         uint16       `json:"rows"`
	Term         string       `json:"term"`
	GrantJTI     string       `json:"grant_jti,omitempty"`
	BuildNonce   string       `json:"build_nonce,omitempty"`
	Capabilities []Capability `json:"capabilities,omitempty"`
}

type OpenAuthorizedSession struct {
	Cols            uint16       `json:"cols"`
	Rows            uint16       `json:"rows"`
	Term            string       `json:"term"`
	ConnectionGrant string       `json:"connection_grant"`
	BuildNonce      string       `json:"build_nonce,omitempty"`
	Capabilities    []Capability `json:"capabilities,omitempty"`
}

type AgentBuildIdentity struct {
	DeviceID     string `json:"device_id"`
	Nonce        string `json:"nonce"`
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	SourceSHA256 string `json:"source_sha256"`
	BuiltAt      string `json:"built_at"`
	Go           string `json:"go"`
	Platform     string `json:"platform"`
	Signature    string `json:"signature"`
}

type SessionAccepted struct {
	Capabilities  []Capability        `json:"capabilities,omitempty"`
	BuildIdentity *AgentBuildIdentity `json:"build_identity,omitempty"`
}

type Resize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

type Close struct {
	ExitCode int    `json:"exit_code"`
	Reason   string `json:"reason,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func JSON(v any) ([]byte, error)         { return json.Marshal(v) }
func ParseJSON(data []byte, v any) error { return json.Unmarshal(data, v) }
