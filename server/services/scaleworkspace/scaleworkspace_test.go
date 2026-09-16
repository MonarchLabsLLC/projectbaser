// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package scaleworkspace

import (
	"encoding/json"
	"net/http"
	"testing"
)

const testContextJSON = `{
  "version": 1,
  "actor": {"keycloakSubject":"member-subject","email":"member@example.com"},
  "workspace": {"id":"workspace-id","displayName":"Owner Team","type":"guest"},
  "owner": {"keycloakSubject":"owner-subject","displayName":"Owner","email":"owner@example.com"},
  "membership": {"role":"member","status":"active"},
  "application": {"slug":"projectbaser","capability":"general-member"},
  "authorizationVersion":"version", "expiresAt":"2026-12-01T00:00:00Z"
}`

func testContext(t *testing.T, mutate func(*Context)) *Context {
	t.Helper()
	var context Context
	if err := json.Unmarshal([]byte(testContextJSON), &context); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&context)
	}
	return &context
}

func TestValidateContextBindsAnActiveMemberToProjectBaser(t *testing.T) {
	if err := ValidateContext(testContext(t, nil)); err != nil {
		t.Fatalf("expected valid context: %v", err)
	}
	for name, mutate := range map[string]func(*Context){
		"different app":  func(c *Context) { c.Application.Slug = "other" },
		"owner role":     func(c *Context) { c.Membership.Role = "owner" },
		"revoked member": func(c *Context) { c.Membership.Status = "revoked" },
		"personal scope": func(c *Context) { c.Workspace.Type = "personal" },
		"empty actor":    func(c *Context) { c.Actor.KeycloakSubject = "" },
		"bad expiry":     func(c *Context) { c.ExpiresAt = "never" },
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateContext(testContext(t, mutate)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestClassifyIsAnAllowlist(t *testing.T) {
	allowed := []struct{ method, path string }{
		{http.MethodGet, "/api/v2/boards/board"}, {http.MethodPatch, "/api/v2/boards/board/blocks/card"},
		{http.MethodPost, "/api/v2/teams/team/categories"}, {http.MethodGet, "/api/v2/users/me"},
		{http.MethodPost, "/api/v2/scale-workspace/leave"},
	}
	for _, test := range allowed {
		if got := Classify(test.method, test.path); got != DecisionAllow {
			t.Errorf("%s %s: got %v", test.method, test.path, got)
		}
	}
	denied := []struct{ method, path string }{
		{http.MethodPost, "/api/v2/register"}, {http.MethodPost, "/api/v2/teams/team/regenerate_signup_token"},
		{http.MethodGet, "/api/v2/boards/board/sharing"}, {http.MethodGet, "/api/v2/new-owner-surface"},
	}
	for _, test := range denied {
		if got := Classify(test.method, test.path); got != DecisionDeny {
			t.Errorf("%s %s: got %v", test.method, test.path, got)
		}
	}
}

func TestAdapterDefaultsToOffAndSanitizesCallbackValues(t *testing.T) {
	t.Setenv("SCALE_TEAM_WORKSPACES_ENABLED", "")
	if Enabled() {
		t.Fatal("adapter must default to off")
	}
	t.Setenv("SCALE_TEAM_WORKSPACES_ENABLED", "true")
	if !Enabled() {
		t.Fatal("adapter must accept literal true")
	}
	if SanitizeReturnPath("//attacker.example") != "/" || SanitizeReturnPath("/boards/ok") != "/boards/ok" {
		t.Fatal("return path handling is unsafe")
	}
	if !ValidLaunchCode("launch-code_123") || ValidLaunchCode("has space") || ValidLaunchCode("") {
		t.Fatal("launch code validation is wrong")
	}
}
