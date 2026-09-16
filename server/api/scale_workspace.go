// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mattermost/focalboard/server/model"
	"github.com/mattermost/focalboard/server/services/auth"
	"github.com/mattermost/focalboard/server/services/scaleworkspace"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
)

// All workspace behavior is inert unless the explicit environment gate is on.
// The server session holds only a centrally-issued context and a local owner
// team ID; no Keycloak bearer token or workspace data is copied into tables.
func (a *API) registerScaleWorkspaceRoutes(r *mux.Router) {
	r.HandleFunc("/scale-workspace/exchange", a.sessionRequired(a.handleScaleWorkspaceExchange)).Methods(http.MethodPost)
	r.HandleFunc("/scale-workspace/display-context", a.sessionRequired(a.handleScaleWorkspaceDisplayContext)).Methods(http.MethodGet)
	r.HandleFunc("/scale-workspace/leave", a.sessionRequired(a.handleScaleWorkspaceLeave)).Methods(http.MethodPost)
}

func (a *API) registerScaleWorkspacePublicRoutes(r *mux.Router) {
	r.HandleFunc("/auth/scale-workspace/callback", a.handleScaleWorkspaceCallback).Methods(http.MethodGet)
}

func (a *API) handleScaleWorkspaceCallback(w http.ResponseWriter, r *http.Request) {
	if !scaleworkspace.Enabled() {
		http.NotFound(w, r)
		return
	}
	code := r.URL.Query().Get("scale_workspace_code")
	if !scaleworkspace.ValidLaunchCode(code) {
		http.Error(w, "invalid workspace launch code", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/?scale_workspace_code="+url.QueryEscape(code), http.StatusFound)
}

type scaleWorkspaceExchangeRequest struct {
	Code string `json:"code"`
}
type scaleWorkspaceExchangeResponse struct {
	TeamID     string `json:"teamId"`
	ReturnPath string `json:"returnPath"`
}

func (a *API) handleScaleWorkspaceExchange(w http.ResponseWriter, r *http.Request) {
	if !scaleworkspace.Enabled() {
		a.errorResponse(w, r, model.NewErrNotFound("scale-workspace"))
		return
	}
	session, _ := r.Context().Value(sessionContextKey).(*model.Session)
	if session == nil {
		a.errorResponse(w, r, model.NewErrUnauthorized("not authenticated"))
		return
	}
	actorSubject, _ := session.Props["keycloak_sub_id"].(string)
	if actorSubject == "" {
		a.errorResponse(w, r, model.NewErrForbidden("a Keycloak sign-in is required for team workspaces"))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		a.errorResponse(w, r, model.NewErrBadRequest("unable to read workspace launch request"))
		return
	}
	var request scaleWorkspaceExchangeRequest
	if err := json.Unmarshal(body, &request); err != nil || !scaleworkspace.ValidLaunchCode(request.Code) {
		a.errorResponse(w, r, model.NewErrBadRequest("invalid workspace launch code"))
		return
	}
	result, err := scaleworkspace.ExchangeCode(r.Context(), request.Code)
	if err != nil {
		a.logger.Warn("scale workspace exchange rejected", mlog.Err(err))
		a.errorResponse(w, r, model.NewErrForbidden("workspace launch code was rejected"))
		return
	}
	context := result.Context
	if context.Actor.KeycloakSubject != actorSubject || context.Owner.KeycloakSubject == actorSubject {
		a.errorResponse(w, r, model.NewErrForbidden("workspace actor validation failed"))
		return
	}

	// Owner data is never cloned or provisioned for a guest. The only scope we
	// accept is the owner's pre-existing primary tenant in this application.
	owner, err := a.app.GetUserByKeycloakSubID(context.Owner.KeycloakSubject)
	if err != nil || owner == nil {
		a.errorResponse(w, r, model.NewErrForbidden("workspace owner is not provisioned in this application"))
		return
	}
	ownerTeam, err := a.app.GetPrimaryTeamForUser(owner.ID)
	if err != nil || ownerTeam == nil {
		a.errorResponse(w, r, model.NewErrForbidden("workspace owner has no local tenant"))
		return
	}
	contextJSON, err := json.Marshal(context)
	if err != nil {
		a.errorResponse(w, r, err)
		return
	}
	if session.Props == nil {
		session.Props = map[string]interface{}{}
	}
	if _, remembered := session.Props[scaleworkspace.SessionPropHomeTeamID].(string); !remembered {
		if homeTeamID, ok := session.Props["team_id"].(string); ok {
			session.Props[scaleworkspace.SessionPropHomeTeamID] = homeTeamID
		}
	}
	session.Props[scaleworkspace.SessionPropContext] = string(contextJSON)
	session.Props[scaleworkspace.SessionPropOwnerTeamID] = ownerTeam.ID
	session.Props[scaleworkspace.SessionPropAllowedApps] = strings.Join(result.AllowedApplications, ",")
	session.Props["team_id"] = ownerTeam.ID
	if err := a.app.UpdateSession(session); err != nil {
		a.errorResponse(w, r, err)
		return
	}
	response, err := json.Marshal(scaleWorkspaceExchangeResponse{TeamID: ownerTeam.ID, ReturnPath: scaleworkspace.SanitizeReturnPath(result.ReturnPath)})
	if err != nil {
		a.errorResponse(w, r, err)
		return
	}
	jsonBytesResponse(w, http.StatusOK, response)
}

type scaleWorkspaceDisplayContext struct {
	WorkspaceType       string   `json:"workspaceType"`
	WorkspaceName       string   `json:"workspaceName"`
	WorkspaceOwnerName  string   `json:"workspaceOwnerName,omitempty"`
	WorkspaceSwitchURL  string   `json:"workspaceSwitchUrl,omitempty"`
	AllowedApplications []string `json:"allowedApplications,omitempty"`
	TeamID              string   `json:"teamId,omitempty"`
}

func (a *API) handleScaleWorkspaceDisplayContext(w http.ResponseWriter, r *http.Request) {
	payload := scaleWorkspaceDisplayContext{WorkspaceType: "personal", WorkspaceName: "Your workspace"}
	if scaleworkspace.Enabled() {
		if session, _ := r.Context().Value(sessionContextKey).(*model.Session); session != nil {
			if raw, ok := session.Props[scaleworkspace.SessionPropContext].(string); ok && raw != "" {
				if context, err := scaleworkspace.ParseContext(raw); err == nil {
					allowed := []string{scaleworkspace.AppSlug}
					if values, ok := session.Props[scaleworkspace.SessionPropAllowedApps].(string); ok && values != "" {
						allowed = strings.Split(values, ",")
					}
					teamID, _ := session.Props[scaleworkspace.SessionPropOwnerTeamID].(string)
					payload = scaleWorkspaceDisplayContext{WorkspaceType: "guest", WorkspaceName: context.Workspace.DisplayName, WorkspaceOwnerName: context.Owner.DisplayName, WorkspaceSwitchURL: scaleworkspace.SwitchURL(), AllowedApplications: allowed, TeamID: teamID}
				}
			}
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		a.errorResponse(w, r, err)
		return
	}
	jsonBytesResponse(w, http.StatusOK, data)
}

func (a *API) handleScaleWorkspaceLeave(w http.ResponseWriter, r *http.Request) {
	if !scaleworkspace.Enabled() {
		a.errorResponse(w, r, model.NewErrNotFound("scale-workspace"))
		return
	}
	session, _ := r.Context().Value(sessionContextKey).(*model.Session)
	if session == nil {
		a.errorResponse(w, r, model.NewErrUnauthorized("not authenticated"))
		return
	}
	data, err := json.Marshal(map[string]string{"teamId": a.clearScaleWorkspaceSession(session)})
	if err != nil {
		a.errorResponse(w, r, err)
		return
	}
	jsonBytesResponse(w, http.StatusOK, data)
}

func (a *API) clearScaleWorkspaceSession(session *model.Session) string {
	if homeTeamID, _ := session.Props[scaleworkspace.SessionPropHomeTeamID].(string); homeTeamID != "" {
		session.Props["team_id"] = homeTeamID
	}
	delete(session.Props, scaleworkspace.SessionPropContext)
	delete(session.Props, scaleworkspace.SessionPropOwnerTeamID)
	delete(session.Props, scaleworkspace.SessionPropHomeTeamID)
	delete(session.Props, scaleworkspace.SessionPropAllowedApps)
	if err := a.app.UpdateSession(session); err != nil {
		a.logger.Error("failed to clear scale workspace session", mlog.Err(err))
	}
	teamID, _ := session.Props["team_id"].(string)
	return teamID
}

// scaleWorkspaceGuard performs the central authorization check before every
// guest request. Unknown and sensitive routes fail closed. Transient hub
// errors deny access without destroying a potentially valid session; a 4xx
// revocation clears it and restores the member's own team.
func (a *API) scaleWorkspaceGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !scaleworkspace.Enabled() {
			next.ServeHTTP(w, r)
			return
		}
		token, _ := auth.ParseAuthTokenFromRequest(r)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		session, err := a.app.GetSession(token)
		if err != nil || session == nil {
			next.ServeHTTP(w, r)
			return
		}
		raw, guest := session.Props[scaleworkspace.SessionPropContext].(string)
		if !guest || raw == "" {
			next.ServeHTTP(w, r)
			return
		}
		if scaleworkspace.Classify(r.Method, r.URL.Path) != scaleworkspace.DecisionAllow {
			jsonBytesResponse(w, http.StatusForbidden, []byte(`{"error":"this action is owner-only in a guest workspace"}`))
			return
		}
		stored, err := scaleworkspace.ParseContext(raw)
		if err != nil {
			a.clearScaleWorkspaceSession(session)
			jsonBytesResponse(w, http.StatusForbidden, []byte(`{"error":"guest workspace context is invalid"}`))
			return
		}
		keycloakToken := r.Header.Get(scaleworkspace.KeycloakTokenHeader)
		if keycloakToken == "" {
			jsonBytesResponse(w, http.StatusUnauthorized, []byte(`{"error":"a current keycloak token is required for guest workspace access"}`))
			return
		}
		result, err := scaleworkspace.Authorize(r.Context(), stored.Workspace.ID, keycloakToken)
		if err != nil {
			if errors.Is(err, scaleworkspace.ErrAccessRevoked) {
				a.clearScaleWorkspaceSession(session)
				jsonBytesResponse(w, http.StatusConflict, []byte(`{"code":"WORKSPACE_ACCESS_REVOKED","error":"guest workspace access is no longer active","redirectUrl":"/"}`))
				return
			}
			jsonBytesResponse(w, http.StatusServiceUnavailable, []byte(`{"error":"guest workspace authorization is temporarily unavailable"}`))
			return
		}
		actorSubject, _ := session.Props["keycloak_sub_id"].(string)
		ownerTeamID, _ := session.Props[scaleworkspace.SessionPropOwnerTeamID].(string)
		// Re-resolve owner tenant on every guest request. This prevents a stale
		// session from becoming a cross-owner scope if central ownership changes.
		owner, ownerErr := a.app.GetUserByKeycloakSubID(result.Context.Owner.KeycloakSubject)
		if ownerErr != nil || owner == nil {
			a.clearScaleWorkspaceSession(session)
			jsonBytesResponse(w, http.StatusForbidden, []byte(`{"error":"workspace scope validation failed"}`))
			return
		}
		ownerTeam, teamErr := a.app.GetPrimaryTeamForUser(owner.ID)
		if actorSubject == "" || teamErr != nil || ownerTeam == nil ||
			result.Context.Actor.KeycloakSubject != actorSubject || result.Context.Workspace.ID != stored.Workspace.ID ||
			result.Context.Owner.KeycloakSubject != stored.Owner.KeycloakSubject || ownerTeam.ID != ownerTeamID {
			a.clearScaleWorkspaceSession(session)
			jsonBytesResponse(w, http.StatusForbidden, []byte(`{"error":"workspace scope validation failed"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
