package api

import (
	"context"
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

// KeycloakTokenClaims represents the verified JWT claims from Keycloak
type KeycloakTokenClaims struct {
	Issuer            string                 `json:"iss"`
	Audience          keycloakAudience       `json:"aud"`
	AuthorizedParty   string                 `json:"azp"`
	Type              string                 `json:"typ"`
	ExpiresAt         *float64               `json:"exp"`
	NotBefore         *float64               `json:"nbf"`
	IssuedAt          *float64               `json:"iat"`
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

	cfg := a.app.GetConfig()
	if cfg == nil {
		a.errorResponse(w, r, model.NewErrUnauthorized("invalid token"))
		return
	}
	verifier, err := keycloakVerifierFor(cfg.KeycloakBaseURL, cfg.KeycloakRealm, cfg.KeycloakClientID)
	if err != nil {
		a.logger.Error("Keycloak token login is not configured", mlog.Err(err))
		a.errorResponse(w, r, model.NewErrUnauthorized("invalid token"))
		return
	}
	claims, err := verifier.Verify(r.Context(), token)
	if err != nil {
		a.logger.Warn("Rejected Keycloak token", mlog.Err(err))
		a.errorResponse(w, r, model.NewErrUnauthorized("invalid token"))
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

	// Get or create user via app layer. A changed email is adopted only after
	// Keycloak's userinfo endpoint also confirms it for this token.
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
