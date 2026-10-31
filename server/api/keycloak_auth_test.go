package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHasRequiredRole(t *testing.T) {
	tests := []struct {
		name   string
		claims KeycloakTokenClaims
		want   bool
	}{
		{
			name: "accepts ProjectBaser client role",
			claims: KeycloakTokenClaims{ResourceAccess: map[string]interface{}{
				"app-projectbaser": map[string]interface{}{
					"roles": []interface{}{requiredKeycloakRole},
				},
			}},
			want: true,
		},
		{
			name: "accepts ProjectBaser realm role",
			claims: KeycloakTokenClaims{RealmAccess: map[string]interface{}{
				"roles": []interface{}{requiredKeycloakRole},
			}},
			want: true,
		},
		{
			name: "rejects role copied from another application",
			claims: KeycloakTokenClaims{RealmAccess: map[string]interface{}{
				"roles": []interface{}{"app_pipeleads"},
			}},
			want: false,
		},
		{
			name:   "rejects missing role",
			claims: KeycloakTokenClaims{},
			want:   false,
		},
	}

	testAPI := &API{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := testAPI.hasRequiredRole(&test.claims, requiredKeycloakRole); got != test.want {
				t.Fatalf("hasRequiredRole() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestFetchKeycloakUserInfoEmail(t *testing.T) {
	var gotAuth string
	status, body := http.StatusOK, `{"sub":"sub-1","email":"new@example.com","email_verified":true}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	ctx := context.Background()

	email, verified, err := fetchKeycloakUserInfoEmail(ctx, server.Client(), server.URL, "access-token", "sub-1")
	if err != nil || email != "new@example.com" || !verified {
		t.Fatalf("got (%q, %v, %v), want verified new@example.com", email, verified, err)
	}
	if gotAuth != "Bearer access-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}

	if _, _, err := fetchKeycloakUserInfoEmail(ctx, server.Client(), server.URL, "access-token", "someone-else"); err == nil {
		t.Fatal("a userinfo subject that does not match the token must be rejected")
	}

	body = `{"sub":"sub-1","email":"new@example.com"}`
	if _, verified, err := fetchKeycloakUserInfoEmail(ctx, server.Client(), server.URL, "t", "sub-1"); err != nil || verified {
		t.Fatalf("missing email_verified must read as unverified, got (%v, %v)", verified, err)
	}

	status = http.StatusUnauthorized
	if _, _, err := fetchKeycloakUserInfoEmail(ctx, server.Client(), server.URL, "forged", "sub-1"); err == nil {
		t.Fatal("a token Keycloak rejects must not confirm an email")
	}
}
