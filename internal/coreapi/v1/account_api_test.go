package v1

import (
	"reflect"
	"strings"
	"testing"
)

func TestAccountWireMethods(t *testing.T) {
	if MethodAccountSignIn != "account.sign_in" {
		t.Fatalf("MethodAccountSignIn = %q", MethodAccountSignIn)
	}
	if MethodAccountSignOut != "account.sign_out" {
		t.Fatalf("MethodAccountSignOut = %q", MethodAccountSignOut)
	}
}

func TestSignInRequestIsCredentialInputOnly(t *testing.T) {
	typ := reflect.TypeOf(SignInRequest{})
	if typ.NumField() != 2 {
		t.Fatalf("SignInRequest field count = %d, want 2", typ.NumField())
	}
	want := map[string]bool{"email": false, "password": false}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		wireName := strings.Split(field.Tag.Get("json"), ",")[0]
		if _, ok := want[wireName]; !ok {
			t.Fatalf("SignInRequest exposes unexpected field %q", wireName)
		}
		want[wireName] = true
	}
	for wireName, seen := range want {
		if !seen {
			t.Fatalf("SignInRequest missing %q", wireName)
		}
	}
}
