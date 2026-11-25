package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validPortForwardTestConfig(apiKey string) serveConfig {
	return serveConfig{
		PortForwardAuthorizationPublicKey: "test-ed25519-public-key",
		PortForwardReplayURL:              "https://project.supabase.co/functions/v1/port-forward-replay",
		PortForwardReplayAPIKey:           apiKey,
		PortForwardAllowedPorts:           "443",
		PortForwardMaxConnections:         1,
	}
}

func TestValidatePortForwardRejectsPrivilegedSupabaseKeys(t *testing.T) {
	serviceRoleJWT := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"role":"service_role"}`)) + ".signature"
	for _, key := range []string{"sb_secret_test", serviceRoleJWT} {
		t.Run(key[:min(len(key), 12)], func(t *testing.T) {
			err := validPortForwardTestConfig(key).validatePortForward()
			if err == nil || !strings.Contains(err.Error(), "service-role credentials") {
				t.Fatalf("privileged Supabase credential was accepted: %v", err)
			}
		})
	}
}

func TestValidatePortForwardAllowsPublicSupabaseKey(t *testing.T) {
	if err := validPortForwardTestConfig("sb_publishable_test").validatePortForward(); err != nil {
		t.Fatalf("public Supabase key rejected: %v", err)
	}
}
