// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import "github.com/mattermost/focalboard/server/model"

// GetUserByKeycloakSubID and UpdateSession are the narrow app-layer methods
// required by the workspace adapter. Context remains in server-side sessions.
func (a *App) GetUserByKeycloakSubID(keycloakSubID string) (*model.User, error) {
	return a.store.GetUserByKeycloakSubID(keycloakSubID)
}

func (a *App) UpdateSession(session *model.Session) error { return a.store.UpdateSession(session) }
