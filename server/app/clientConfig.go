package app

import (
	"github.com/mattermost/focalboard/server/model"
	"github.com/mattermost/focalboard/server/services/scaleworkspace"
)

func (a *App) GetClientConfig() *model.ClientConfig {
	return &model.ClientConfig{
		Telemetry:                a.config.Telemetry,
		TelemetryID:              a.config.TelemetryID,
		EnablePublicSharedBoards: a.config.EnablePublicSharedBoards,
		TeammateNameDisplay:      a.config.TeammateNameDisplay,
		FeatureFlags:             a.config.FeatureFlags,
		MaxFileSize:              a.config.MaxFileSize,
		ScaleTeamWorkspaces:      scaleworkspace.Enabled(),
	}
}
