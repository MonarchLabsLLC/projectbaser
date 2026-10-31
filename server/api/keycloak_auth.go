package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattermost/focalboard/server/model"
	"github.com/mattermost/focalboard/server/services/audit"

	"github.com/mattermost/mattermost/server/public/shared/mlog"
)

const requiredKeycloakRole = "app_projectbaser"

// KeycloakTokenClaims represents the decoded JWT claims from Keycloak
type KeycloakTokenClaims struct {
	Sub               string                 `json:"sub"`
	Email             string                 `json:"email"`
	EmailVerified     bool                   `json:"email_verified"`
	PreferredUsername string                 `json:"preferred_username"`
	GivenName         string                 `json:"given_name"`
	FamilyName        string                 `json:"family_name"`
	Name              string                 `json:"name"`
	ResourceAccess    map[string]interface{} `json:"resource_access"`
	RealmAccess       map[string]interface{} `json:"realm_access"`
}

// KeycloakLoginResponse represents the response from keycloak login endpoint
type KeycloakLoginResponse struct {
	Token  string      `json:"token"`
	User   *model.User `json:"user"`
	TeamID string      `json:"teamId"`
}

func (a *API) registerKeycloakAuthRoutes(r *mux.Router) {
	r.HandleFunc("/auth/keycloak-token-login", a.handleKeycloakTokenLogin).Methods("POST")
}

func (a *API) handleKeycloakTokenLogin(w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /auth/keycloak-token-login keycloakTokenLogin
	//
	// Login using Keycloak JWT token
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	// - name: Authorization
	//   in: header
	//   description: Bearer token from Keycloak
	//   required: true
	//   type: string
	// responses:
	//   '200':
	//     description: success
	//     schema:
	//       "$ref": "#/definitions/KeycloakLoginResponse"
	//   '401':
	//     description: invalid token or access denied
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"
	//   '500':
	//     description: internal error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"

	auditRec := a.makeAuditRecord(r, "keycloakTokenLogin", audit.Fail)
	defer a.audit.LogRecord(audit.LevelAuth, auditRec)

	// Extract bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		a.errorResponse(w, r, model.NewErrUnauthorized("missing authorization header"))
		return
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		a.errorResponse(w, r, model.NewErrUnauthorized("invalid authorization header format"))
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		a.errorResponse(w, r, model.NewErrUnauthorized("empty token"))
		return
	}

	// Decode JWT token (without signature verification as per requirements)
	claims, err := a.decodeJWTPayload(token)
	if err != nil {
		a.logger.Error("Failed to decode JWT token", mlog.Err(err))
		a.errorResponse(w, r, model.NewErrUnauthorized("invalid token format"))
		return
	}

	// Validate required claims
	if claims.Sub == "" {
		a.errorResponse(w, r, model.NewErrUnauthorized("missing subject in token"))
		return
	}

	if claims.Email == "" {
		a.errorResponse(w, r, model.NewErrUnauthorized("missing email in token"))
		return
	}

	auditRec.AddMeta("email", claims.Email)
	auditRec.AddMeta("keycloak_sub", claims.Sub)

	// Require the ProjectBaser entitlement before creating an application session.
	if !a.hasRequiredRole(claims, requiredKeycloakRole) {
		a.logger.Warn("User does not have required role",
			mlog.String("email", claims.Email),
			mlog.String("keycloak_sub", claims.Sub))
		a.errorResponse(w, r, model.NewErrForbidden("access denied: missing required role"))
		return
	}

	// Get or create user via app layer
	// The token above is decoded, not verified, so a changed email is adopted
	// only after Keycloak's userinfo endpoint confirms it for this token.
	confirmEmail := func() (string, bool, error) {
		return a.confirmKeycloakEmail(r.Context(), token, claims.Sub)
	}
	sessionToken, user, teamID, err := a.app.KeycloakLogin(claims.Sub, claims.Email, claims.GivenName, claims.FamilyName, confirmEmail)
	if err != nil {
		a.logger.Error("Keycloak login failed", mlog.Err(err))
		a.errorResponse(w, r, model.NewErrUnauthorized("login failed"))
		return
	}

	// Build response
	response := KeycloakLoginResponse{
		Token:  sessionToken,
		User:   user,
		TeamID: teamID,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		a.errorResponse(w, r, err)
		return
	}

	jsonBytesResponse(w, http.StatusOK, jsonBytes)
	auditRec.AddMeta("userID", user.ID)
	auditRec.Success()
}

// decodeJWTPayload decodes the JWT payload without verifying the signature
// This is intentional as per requirements - we trust Keycloak issued the token
func (a *API) decodeJWTPayload(token string) (*KeycloakTokenClaims, error) {
	// JWT structure: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, model.NewErrBadRequest("invalid JWT format")
	}

	// Decode the payload (second part)
	payload := parts[1]

	// Add padding if necessary for base64 decoding
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try standard base64 if URL encoding fails
		decoded, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, err
		}
	}

	var claims KeycloakTokenClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// hasRequiredRole checks if the user has the required role in the token
func (a *API) hasRequiredRole(claims *KeycloakTokenClaims, requiredRole string) bool {
	// Check in resource_access first (client-specific roles)
	for _, access := range claims.ResourceAccess {
		if accessMap, ok := access.(map[string]interface{}); ok {
			if roles, ok := accessMap["roles"].([]interface{}); ok {
				for _, role := range roles {
					if roleStr, ok := role.(string); ok && roleStr == requiredRole {
						return true
					}
				}
			}
		}
	}

	// Check in realm_access (realm-level roles)
	if claims.RealmAccess != nil {
		if roles, ok := claims.RealmAccess["roles"].([]interface{}); ok {
			for _, role := range roles {
				if roleStr, ok := role.(string); ok && roleStr == requiredRole {
					return true
				}
			}
		}
	}

	return false
}

// handleKeycloakUserInfo returns user info for an authenticated Keycloak session
func (a *API) handleKeycloakUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, ok := ctx.Value(sessionContextKey).(*model.Session)
	if !ok || session == nil {
		a.errorResponse(w, r, model.NewErrUnauthorized("not authenticated"))
		return
	}

	user, err := a.app.GetUser(session.UserID)
	if err != nil {
		a.errorResponse(w, r, err)
		return
	}

	jsonBytes, err := json.Marshal(user)
	if err != nil {
		a.errorResponse(w, r, err)
		return
	}

	jsonBytesResponse(w, http.StatusOK, jsonBytes)
}

var keycloakUserInfoClient = &http.Client{Timeout: 5 * time.Second}

type keycloakUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// confirmKeycloakEmail asks the configured Keycloak realm which email it
// vouches for on this access token.
func (a *API) confirmKeycloakEmail(ctx context.Context, token, expectedSub string) (string, bool, error) {
	cfg := a.app.GetConfig()
	if cfg == nil || cfg.KeycloakBaseURL == "" || cfg.KeycloakRealm == "" {
		return "", false, errors.New("keycloak is not configured")
	}
	userInfoURL := strings.TrimRight(cfg.KeycloakBaseURL, "/") + "/realms/" + url.PathEscape(cfg.KeycloakRealm) +
		"/protocol/openid-connect/userinfo"
	return fetchKeycloakUserInfoEmail(ctx, keycloakUserInfoClient, userInfoURL, token, expectedSub)
}

func fetchKeycloakUserInfoEmail(ctx context.Context, client *http.Client, userInfoURL, token, expectedSub string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("keycloak userinfo returned status %d", resp.StatusCode)
	}

	var info keycloakUserInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&info); err != nil {
		return "", false, err
	}
	if info.Sub == "" || info.Sub != expectedSub {
		return "", false, errors.New("keycloak userinfo subject does not match the token")
	}
	return info.Email, info.EmailVerified, nil
}
