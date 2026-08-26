package enrollment

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const Domain = "wedecent-enrollment-v1"

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	deviceIDPattern = regexp.MustCompile(`^wd_[a-z2-7]{16}$`)
)

type ProofFields struct {
	ChallengeID    string
	Challenge      string
	UserID         string
	DeviceID       string
	PublicKey      string
	Kind           string
	OrganizationID string
	ExpiresUnixMS  int64
}

func Message(f ProofFields) ([]byte, error) {
	if !uuidPattern.MatchString(f.ChallengeID) {
		return nil, errors.New("challenge ID must be a UUID")
	}
	if !uuidPattern.MatchString(f.UserID) {
		return nil, errors.New("user ID must be a UUID")
	}
	if !deviceIDPattern.MatchString(f.DeviceID) {
		return nil, errors.New("invalid device ID")
	}
	if f.Kind != "client" && f.Kind != "agent" && f.Kind != "hybrid" {
		return nil, errors.New("kind must be client, agent, or hybrid")
	}
	if f.OrganizationID != "" && !uuidPattern.MatchString(f.OrganizationID) {
		return nil, errors.New("organization ID must be a UUID")
	}
	if f.ExpiresUnixMS <= 0 {
		return nil, errors.New("expires-unix-ms must be positive")
	}

	challenge, err := base64.RawURLEncoding.DecodeString(f.Challenge)
	if err != nil || len(challenge) != 32 {
		return nil, errors.New("challenge must be 32 raw bytes encoded as base64url without padding")
	}
	pub, err := base64.RawURLEncoding.DecodeString(f.PublicKey)
	if err != nil || len(pub) != 32 {
		return nil, errors.New("public key must be 32 raw bytes encoded as base64url without padding")
	}

	org := f.OrganizationID
	if org == "" {
		org = "-"
	}
	values := []string{f.ChallengeID, f.Challenge, f.UserID, f.DeviceID, f.PublicKey, f.Kind, org}
	for _, value := range values {
		if strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("enrollment fields must not contain newlines")
		}
	}

	return []byte(fmt.Sprintf(
		"%s\nchallenge_id=%s\nchallenge=%s\nuser_id=%s\ndevice_id=%s\npublic_key=%s\nkind=%s\norganization_id=%s\nexpires_unix_ms=%d\n",
		Domain,
		f.ChallengeID,
		f.Challenge,
		f.UserID,
		f.DeviceID,
		f.PublicKey,
		f.Kind,
		org,
		f.ExpiresUnixMS,
	)), nil
}
