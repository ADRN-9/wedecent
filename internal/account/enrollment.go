package account

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const enrollmentKindClient = "client"

type DeviceEnrollmentRequest struct {
	Action         string `json:"action"`
	DeviceID       string `json:"device_id"`
	PublicKey      string `json:"public_key"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id,omitempty"`
}

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
	ChallengeID    string `json:"challenge_id"`
	Challenge      string `json:"challenge"`
	DeviceID       string `json:"device_id"`
	PublicKey      string `json:"public_key"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id,omitempty"`
	ExpiresUnixMS  int64  `json:"expires_unix_ms"`
	Signature      string `json:"signature"`
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

func (c Client) RequestDeviceEnrollmentChallenge(ctx context.Context, session *Session, device DeviceEnrollmentRequest) (EnrollmentChallenge, error) {
	if session == nil {
		return EnrollmentChallenge{}, errors.New("account session is nil")
	}
	if err := session.validate(); err != nil {
		return EnrollmentChallenge{}, fmt.Errorf("invalid account session: %w", err)
	}
	if strings.TrimSpace(session.UserID) == "" {
		return EnrollmentChallenge{}, errors.New("account session user ID is missing")
	}

	device.Action = strings.TrimSpace(device.Action)
	device.DeviceID = strings.TrimSpace(device.DeviceID)
	device.PublicKey = strings.TrimSpace(device.PublicKey)
	device.Kind = strings.TrimSpace(device.Kind)
	device.Name = strings.TrimSpace(device.Name)
	device.OrganizationID = strings.TrimSpace(device.OrganizationID)
	if device.Action != "" && device.Action != "challenge" {
		return EnrollmentChallenge{}, errors.New("device enrollment request action must be challenge")
	}
	if err := validateEnrollmentKind(device.Kind); err != nil {
		return EnrollmentChallenge{}, err
	}
	if err := validateEnrollmentIdentity(device.DeviceID, device.PublicKey, device.Name); err != nil {
		return EnrollmentChallenge{}, err
	}

	request := map[string]any{
		"action":     "challenge",
		"device_id":  device.DeviceID,
		"public_key": device.PublicKey,
		"kind":       device.Kind,
		"name":       device.Name,
	}
	if device.OrganizationID != "" {
		request["organization_id"] = device.OrganizationID
	}

	var response EnrollmentChallenge
	if err := c.doJSON(ctx, "POST", session.SupabaseURL+"/functions/v1/device-enrollment", session.PublishableKey, session.AccessToken, request, &response); err != nil {
		return EnrollmentChallenge{}, fmt.Errorf("request device enrollment challenge: %w", err)
	}
	if err := c.validateEnrollmentChallenge(session, response, device.DeviceID, device.PublicKey, device.Kind, device.Name, device.OrganizationID); err != nil {
		return EnrollmentChallenge{}, err
	}
	return response, nil
}

func (c Client) RequestClientEnrollmentChallenge(ctx context.Context, session *Session, deviceID, publicKey, name, organizationID string) (EnrollmentChallenge, error) {
	return c.RequestDeviceEnrollmentChallenge(ctx, session, DeviceEnrollmentRequest{
		Action:         "challenge",
		DeviceID:       deviceID,
		PublicKey:      publicKey,
		Kind:           enrollmentKindClient,
		Name:           name,
		OrganizationID: organizationID,
	})
}

func (c Client) CompleteDeviceEnrollment(ctx context.Context, session *Session, proof DeviceEnrollmentProof) (EnrolledDevice, error) {
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

	if err := validateEnrollmentKind(proof.Kind); err != nil {
		return EnrolledDevice{}, err
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
		"kind":            proof.Kind,
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
	if response.Device.DeviceID != proof.DeviceID || response.Device.PublicKey != proof.PublicKey || response.Device.Kind != proof.Kind || response.Device.Name != proof.Name {
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

func (c Client) CompleteClientEnrollment(ctx context.Context, session *Session, proof DeviceEnrollmentProof) (EnrolledDevice, error) {
	if strings.TrimSpace(proof.Kind) != enrollmentKindClient {
		return EnrolledDevice{}, errors.New("wd client enrollment kind must be client")
	}
	return c.CompleteDeviceEnrollment(ctx, session, proof)
}

func (c Client) validateEnrollmentChallenge(session *Session, response EnrollmentChallenge, deviceID, publicKey, kind, name, organizationID string) error {
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
	if response.DeviceID != deviceID || response.PublicKey != publicKey || response.Kind != kind || response.Name != name {
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

func validateEnrollmentKind(kind string) error {
	switch strings.TrimSpace(kind) {
	case "client", "agent", "hybrid":
		return nil
	default:
		return errors.New("device kind must be client, agent, or hybrid")
	}
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
