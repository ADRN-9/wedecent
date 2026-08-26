package account

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const enrollmentKindClient = "client"

type EnrollmentChallenge struct {
	Action         string `json:"action"`
	ChallengeID    string `json:"challenge_id"`
	Challenge      string `json:"challenge"`
	UserID         string `json:"user_id"`
	DeviceID       string `json:"device_id"`
	PublicKey      string `json:"public_key"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id"`
	ExpiresUnixMS  int64  `json:"expires_unix_ms"`
}

type DeviceEnrollmentProof struct {
	ChallengeID    string
	Challenge      string
	DeviceID       string
	PublicKey      string
	Kind           string
	Name           string
	OrganizationID string
	ExpiresUnixMS  int64
	Signature      string
}

type EnrolledDevice struct {
	DeviceID       string `json:"device_id"`
	PublicKey      string `json:"public_key"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	OwnerUserID    string `json:"owner_user_id"`
	OrganizationID string `json:"organization_id"`
}

type enrollmentCompleteResponse struct {
	Action string         `json:"action"`
	Device EnrolledDevice `json:"device"`
}

func (c Client) RequestClientEnrollmentChallenge(ctx context.Context, session *Session, deviceID, publicKey, name, organizationID string) (EnrollmentChallenge, error) {
	if session == nil {
		return EnrollmentChallenge{}, errors.New("account session is nil")
	}
	if err := session.validate(); err != nil {
		return EnrollmentChallenge{}, fmt.Errorf("invalid account session: %w", err)
	}
	if strings.TrimSpace(session.UserID) == "" {
		return EnrollmentChallenge{}, errors.New("account session user ID is missing")
	}

	deviceID = strings.TrimSpace(deviceID)
	publicKey = strings.TrimSpace(publicKey)
	name = strings.TrimSpace(name)
	organizationID = strings.TrimSpace(organizationID)
	if err := validateEnrollmentIdentity(deviceID, publicKey, name); err != nil {
		return EnrollmentChallenge{}, err
	}

	request := map[string]any{
		"action":     "challenge",
		"device_id":  deviceID,
		"public_key": publicKey,
		"kind":       enrollmentKindClient,
		"name":       name,
	}
	if organizationID != "" {
		request["organization_id"] = organizationID
	}

	var response EnrollmentChallenge
	if err := c.doJSON(ctx, "POST", session.SupabaseURL+"/functions/v1/device-enrollment", session.PublishableKey, session.AccessToken, request, &response); err != nil {
		return EnrollmentChallenge{}, fmt.Errorf("request device enrollment challenge: %w", err)
	}
	if err := c.validateEnrollmentChallenge(session, response, deviceID, publicKey, name, organizationID); err != nil {
		return EnrollmentChallenge{}, err
	}
	return response, nil
}

func (c Client) CompleteClientEnrollment(ctx context.Context, session *Session, proof DeviceEnrollmentProof) (EnrolledDevice, error) {
	if session == nil {
		return EnrolledDevice{}, errors.New("account session is nil")
	}
	if err := session.validate(); err != nil {
		return EnrolledDevice{}, fmt.Errorf("invalid account session: %w", err)
	}
	if strings.TrimSpace(session.UserID) == "" {
		return EnrolledDevice{}, errors.New("account session user ID is missing")
	}

	proof.ChallengeID = strings.TrimSpace(proof.ChallengeID)
	proof.Challenge = strings.TrimSpace(proof.Challenge)
	proof.DeviceID = strings.TrimSpace(proof.DeviceID)
	proof.PublicKey = strings.TrimSpace(proof.PublicKey)
	proof.Kind = strings.TrimSpace(proof.Kind)
	proof.Name = strings.TrimSpace(proof.Name)
	proof.OrganizationID = strings.TrimSpace(proof.OrganizationID)
	proof.Signature = strings.TrimSpace(proof.Signature)

	if proof.Kind != enrollmentKindClient {
		return EnrolledDevice{}, errors.New("wd client enrollment kind must be client")
	}
	if err := validateEnrollmentIdentity(proof.DeviceID, proof.PublicKey, proof.Name); err != nil {
		return EnrolledDevice{}, err
	}
	challengeBytes, err := base64.RawURLEncoding.DecodeString(proof.Challenge)
	if err != nil || len(challengeBytes) != 32 {
		return EnrolledDevice{}, errors.New("enrollment challenge must be 32 raw bytes encoded as base64url")
	}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(proof.Signature)
	if err != nil || len(signatureBytes) != 64 {
		return EnrolledDevice{}, errors.New("enrollment signature must be 64 raw bytes encoded as base64url")
	}
	if proof.ChallengeID == "" || proof.ExpiresUnixMS <= 0 {
		return EnrolledDevice{}, errors.New("enrollment proof is missing challenge metadata")
	}

	request := map[string]any{
		"action":          "complete",
		"challenge_id":    proof.ChallengeID,
		"challenge":       proof.Challenge,
		"device_id":       proof.DeviceID,
		"public_key":      proof.PublicKey,
		"kind":            enrollmentKindClient,
		"name":            proof.Name,
		"expires_unix_ms": proof.ExpiresUnixMS,
		"signature":       proof.Signature,
	}
	if proof.OrganizationID != "" {
		request["organization_id"] = proof.OrganizationID
	}

	var response enrollmentCompleteResponse
	if err := c.doJSON(ctx, "POST", session.SupabaseURL+"/functions/v1/device-enrollment", session.PublishableKey, session.AccessToken, request, &response); err != nil {
		return EnrolledDevice{}, fmt.Errorf("complete device enrollment: %w", err)
	}
	if response.Action != "complete" {
		return EnrolledDevice{}, errors.New("device enrollment service returned an unexpected action")
	}
	if response.Device.DeviceID != proof.DeviceID || response.Device.PublicKey != proof.PublicKey || response.Device.Kind != enrollmentKindClient || response.Device.Name != proof.Name {
		return EnrolledDevice{}, errors.New("device enrollment service returned a mismatched device identity")
	}
	if response.Device.OwnerUserID != session.UserID {
		return EnrolledDevice{}, errors.New("device enrollment service returned a mismatched owner")
	}
	if response.Device.OrganizationID != proof.OrganizationID {
		return EnrolledDevice{}, errors.New("device enrollment service returned a mismatched organization")
	}
	return response.Device, nil
}

func (c Client) validateEnrollmentChallenge(session *Session, response EnrollmentChallenge, deviceID, publicKey, name, organizationID string) error {
	if response.Action != "challenge" {
		return errors.New("device enrollment service returned an unexpected action")
	}
	if response.ChallengeID == "" {
		return errors.New("device enrollment service returned an empty challenge ID")
	}
	challengeBytes, err := base64.RawURLEncoding.DecodeString(response.Challenge)
	if err != nil || len(challengeBytes) != 32 {
		return errors.New("device enrollment service returned an invalid challenge")
	}
	if response.UserID != session.UserID {
		return errors.New("device enrollment service returned a mismatched user")
	}
	if response.DeviceID != deviceID || response.PublicKey != publicKey || response.Kind != enrollmentKindClient || response.Name != name {
		return errors.New("device enrollment service returned a mismatched device challenge")
	}
	if response.OrganizationID != organizationID {
		return errors.New("device enrollment service returned a mismatched organization")
	}

	if response.ExpiresUnixMS <= 0 {
		return errors.New("device enrollment service returned an invalid challenge expiry")
	}
	return nil
}

func validateEnrollmentIdentity(deviceID, publicKey, name string) error {
	if len(deviceID) != 19 || !strings.HasPrefix(deviceID, "wd_") {
		return errors.New("invalid WeDecent device ID")
	}
	for _, r := range deviceID[3:] {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz234567", r) {
			return errors.New("invalid WeDecent device ID")
		}
	}
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(publicKeyBytes) != 32 {
		return errors.New("device public key must be 32 raw bytes encoded as base64url")
	}
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\r\n") {
		return errors.New("device name must contain 1 to 128 characters without newlines")
	}
	return nil
}
