// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// Package scaleworkspace implements ProjectBaser's disabled-by-default
// Scale Plus Team Workspaces contract. Authorization stays at the central
// hub; this package never persists Keycloak access tokens or client secrets.
package scaleworkspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const AppSlug = "projectbaser"
const KeycloakTokenHeader = "X-Scale-Keycloak-Token"

const (
	SessionPropContext     = "scale_workspace_context"
	SessionPropOwnerTeamID = "scale_workspace_owner_team_id"
	SessionPropHomeTeamID  = "scale_workspace_home_team_id"
	SessionPropAllowedApps = "scale_workspace_allowed_apps"
)

const defaultHubURL = "https://app.scaleplus.gg"

var (
	ErrAccessRevoked = errors.New("scale workspace access revoked")
	ErrNotConfigured = errors.New("scale workspace client credentials are not configured")
	httpClient       = &http.Client{Timeout: 5 * time.Second}
)

// Enabled intentionally accepts only the literal "true". A missing or
// malformed production setting must leave the integration inert.
func Enabled() bool { return os.Getenv("SCALE_TEAM_WORKSPACES_ENABLED") == "true" }

func HubURL() string {
	raw := strings.TrimSpace(os.Getenv("SCALE_WORKSPACE_HUB_URL"))
	if raw == "" {
		raw = defaultHubURL
	}
	return strings.TrimRight(raw, "/")
}

func SwitchURL() string { return HubURL() + "/team" }

// Context is the strict WorkspaceContextV1 payload issued by the central hub.
type Context struct {
	Version int `json:"version"`
	Actor   struct {
		KeycloakSubject string `json:"keycloakSubject"`
		Email           string `json:"email"`
	} `json:"actor"`
	Workspace struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Type        string `json:"type"`
	} `json:"workspace"`
	Owner struct {
		KeycloakSubject string `json:"keycloakSubject"`
		DisplayName     string `json:"displayName"`
		Email           string `json:"email"`
	} `json:"owner"`
	Membership struct {
		Role   string `json:"role"`
		Status string `json:"status"`
	} `json:"membership"`
	Application struct {
		Slug       string `json:"slug"`
		Capability string `json:"capability"`
	} `json:"application"`
	AuthorizationVersion string `json:"authorizationVersion"`
	ExpiresAt            string `json:"expiresAt"`
}

func ValidateContext(c *Context) error {
	if c == nil || c.Version != 1 || c.Workspace.Type != "guest" ||
		c.Membership.Role != "member" || c.Membership.Status != "active" ||
		c.Application.Slug != AppSlug || c.Application.Capability != "general-member" ||
		strings.TrimSpace(c.Actor.KeycloakSubject) == "" ||
		strings.TrimSpace(c.Owner.KeycloakSubject) == "" ||
		strings.TrimSpace(c.Workspace.ID) == "" {
		return errors.New("invalid workspace context")
	}
	if _, err := time.Parse(time.RFC3339, c.ExpiresAt); err != nil {
		return errors.New("invalid workspace context expiry")
	}
	return nil
}

func ParseContext(raw string) (*Context, error) {
	var context Context
	if err := json.Unmarshal([]byte(raw), &context); err != nil {
		return nil, errors.New("workspace context is malformed")
	}
	if err := ValidateContext(&context); err != nil {
		return nil, err
	}
	return &context, nil
}

type Decision int

const (
	DecisionDeny Decision = iota
	DecisionAllow
)

type allowRule struct {
	pattern *regexp.Regexp
	methods map[string]bool
}

func methods(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^/admin(/|$)`), regexp.MustCompile(`^/login$`), regexp.MustCompile(`^/register$`),
	regexp.MustCompile(`^/users/[^/]+/changepassword$`), regexp.MustCompile(`^/teams/[^/]+/regenerate_signup_token$`),
	regexp.MustCompile(`^/boards/[^/]+/sharing(/|$)`), regexp.MustCompile(`^/teams/[^/]+/archive/(import|export)$`),
	regexp.MustCompile(`^/statistics$`), regexp.MustCompile(`^/compliance(/|$)`), regexp.MustCompile(`^/channels(/|$)`),
}

var allowRules = []allowRule{
	{regexp.MustCompile(`^/boards(/|$)`), nil}, {regexp.MustCompile(`^/boards-and-blocks(/|$)`), nil},
	{regexp.MustCompile(`^/cards(/|$)`), nil}, {regexp.MustCompile(`^/content-blocks(/|$)`), nil},
	{regexp.MustCompile(`^/teams$`), methods(http.MethodGet)}, {regexp.MustCompile(`^/teams/[^/]+$`), methods(http.MethodGet)},
	{regexp.MustCompile(`^/teams/[^/]+/boards(/|$)`), nil}, {regexp.MustCompile(`^/teams/[^/]+/templates$`), methods(http.MethodGet)},
	{regexp.MustCompile(`^/teams/[^/]+/categories(/|$)`), nil}, {regexp.MustCompile(`^/teams/[^/]+/users$`), methods(http.MethodGet, http.MethodPost)},
	{regexp.MustCompile(`^/teams/[^/]+/onboard$`), methods(http.MethodPost)}, {regexp.MustCompile(`^/teams/[^/]+/[^/]+/files$`), methods(http.MethodPost)},
	{regexp.MustCompile(`^/files/teams/`), methods(http.MethodGet)}, {regexp.MustCompile(`^/subscriptions(/|$)`), nil},
	{regexp.MustCompile(`^/users$`), methods(http.MethodPost)}, {regexp.MustCompile(`^/users/me$`), methods(http.MethodGet)},
	{regexp.MustCompile(`^/users/me/memberships$`), methods(http.MethodGet)}, {regexp.MustCompile(`^/users/me/config$`), methods(http.MethodGet)},
	{regexp.MustCompile(`^/users/[^/]+$`), methods(http.MethodGet)}, {regexp.MustCompile(`^/users/[^/]+/config$`), methods(http.MethodPut)},
	{regexp.MustCompile(`^/logout$`), methods(http.MethodPost)}, {regexp.MustCompile(`^/clientConfig$`), methods(http.MethodGet)},
	{regexp.MustCompile(`^/scale-workspace/(exchange|display-context|leave)$`), nil},
}

// Classify is deliberately an allowlist: new API routes are owner-only until
// their guest semantics are explicitly reviewed.
func Classify(method, fullPath string) Decision {
	path, ok := strings.CutPrefix(fullPath, "/api/v2")
	if !ok {
		return DecisionDeny
	}
	for _, pattern := range sensitivePatterns {
		if pattern.MatchString(path) {
			return DecisionDeny
		}
	}
	for _, rule := range allowRules {
		if rule.pattern.MatchString(path) && (rule.methods == nil || rule.methods[method]) {
			return DecisionAllow
		}
	}
	return DecisionDeny
}

type ExchangeResult struct {
	Context             *Context `json:"context"`
	ReturnPath          string   `json:"returnPath"`
	AllowedApplications []string `json:"allowedApplications"`
}
type AuthorizeResult struct {
	Context             *Context `json:"context"`
	AllowedApplications []string `json:"allowedApplications"`
}

func appHeaders() (http.Header, error) {
	clientID, secret := strings.TrimSpace(os.Getenv("SCALE_WORKSPACE_CLIENT_ID")), strings.TrimSpace(os.Getenv("SCALE_WORKSPACE_CLIENT_SECRET"))
	if clientID == "" || secret == "" {
		return nil, ErrNotConfigured
	}
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Scale-Workspace-Client", clientID)
	headers.Set("X-Scale-Workspace-Secret", secret)
	return headers, nil
}

func postJSON(ctx context.Context, endpoint string, body interface{}, bearer string) (*http.Response, error) {
	headers, err := appHeaders()
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header = headers
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	return httpClient.Do(request)
}

func ExchangeCode(ctx context.Context, code string) (*ExchangeResult, error) {
	response, err := postJSON(ctx, HubURL()+"/api/workspaces/v1/exchange", map[string]string{"code": code}, "")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("workspace launch code rejected: %d", response.StatusCode)
	}
	var result ExchangeResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, errors.New("workspace exchange response was malformed")
	}
	if err := ValidateContext(result.Context); err != nil {
		return nil, err
	}
	return &result, nil
}

func Authorize(ctx context.Context, workspaceID, keycloakToken string) (*AuthorizeResult, error) {
	if strings.TrimSpace(keycloakToken) == "" {
		return nil, errors.New("missing actor keycloak token")
	}
	response, err := postJSON(ctx, HubURL()+"/api/workspaces/v1/authorize", map[string]string{"workspaceId": workspaceID}, keycloakToken)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 && response.StatusCode < 500 {
		return nil, ErrAccessRevoked
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("workspace authorization unavailable: %d", response.StatusCode)
	}
	var result AuthorizeResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, errors.New("workspace authorization response was malformed")
	}
	if err := ValidateContext(result.Context); err != nil {
		return nil, err
	}
	return &result, nil
}

func SanitizeReturnPath(path string) string {
	if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && !strings.ContainsAny(path, "\\\\\r\n") {
		return path
	}
	return "/"
}

func ValidLaunchCode(code string) bool {
	if code == "" || len(code) > 256 {
		return false
	}
	for _, char := range code {
		if char <= ' ' || char > '~' {
			return false
		}
	}
	return true
}
