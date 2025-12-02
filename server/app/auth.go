package app

import (
        "strings"

        "github.com/mattermost/focalboard/server/model"
        "github.com/mattermost/focalboard/server/services/auth"
        "github.com/mattermost/focalboard/server/utils"

        "github.com/mattermost/mattermost/server/public/shared/mlog"

        "github.com/pkg/errors"
)

const (
        DaysPerMonth     = 30
        DaysPerWeek      = 7
        HoursPerDay      = 24
        MinutesPerHour   = 60
        SecondsPerMinute = 60
)

// GetSession Get a user active session and refresh the session if is needed.
func (a *App) GetSession(token string) (*model.Session, error) {
        return a.auth.GetSession(token)
}

// IsValidReadToken validates the read token for a block.
func (a *App) IsValidReadToken(boardID string, readToken string) (bool, error) {
        return a.auth.IsValidReadToken(boardID, readToken)
}

// GetRegisteredUserCount returns the number of registered users.
func (a *App) GetRegisteredUserCount() (int, error) {
        return a.store.GetRegisteredUserCount()
}

// GetDailyActiveUsers returns the number of daily active users.
func (a *App) GetDailyActiveUsers() (int, error) {
        secondsAgo := int64(SecondsPerMinute * MinutesPerHour * HoursPerDay)
        return a.store.GetActiveUserCount(secondsAgo)
}

// GetWeeklyActiveUsers returns the number of weekly active users.
func (a *App) GetWeeklyActiveUsers() (int, error) {
        secondsAgo := int64(SecondsPerMinute * MinutesPerHour * HoursPerDay * DaysPerWeek)
        return a.store.GetActiveUserCount(secondsAgo)
}

// GetMonthlyActiveUsers returns the number of monthly active users.
func (a *App) GetMonthlyActiveUsers() (int, error) {
        secondsAgo := int64(SecondsPerMinute * MinutesPerHour * HoursPerDay * DaysPerMonth)
        return a.store.GetActiveUserCount(secondsAgo)
}

// GetUser gets an existing active user by id.
func (a *App) GetUser(id string) (*model.User, error) {
        if len(id) < 1 {
                return nil, errors.New("no user ID")
        }

        user, err := a.store.GetUserByID(id)
        if err != nil {
                return nil, errors.Wrap(err, "unable to find user")
        }
        return user, nil
}

func (a *App) GetUsersList(userIDs []string) ([]*model.User, error) {
        if len(userIDs) == 0 {
                return nil, errors.New("No User IDs")
        }

        users, err := a.store.GetUsersList(userIDs, a.config.ShowEmailAddress, a.config.ShowFullName)
        if err != nil {
                return nil, errors.Wrap(err, "unable to find users")
        }
        return users, nil
}

// Login create a new user session if the authentication data is valid.
func (a *App) Login(username, email, password, mfaToken string) (string, error) {
        var user *model.User
        if username != "" {
                var err error
                user, err = a.store.GetUserByUsername(username)
                if err != nil && !model.IsErrNotFound(err) {
                        a.metrics.IncrementLoginFailCount(1)
                        return "", errors.Wrap(err, "invalid username or password")
                }
        }

        if user == nil && email != "" {
                var err error
                user, err = a.store.GetUserByEmail(email)
                if err != nil && model.IsErrNotFound(err) {
                        a.metrics.IncrementLoginFailCount(1)
                        return "", errors.Wrap(err, "invalid username or password")
                }
        }

        if user == nil {
                a.metrics.IncrementLoginFailCount(1)
                return "", errors.New("invalid username or password")
        }

        if !auth.ComparePassword(user.Password, password) {
                a.metrics.IncrementLoginFailCount(1)
                a.logger.Debug("Invalid password for user", mlog.String("userID", user.ID))
                return "", errors.New("invalid username or password")
        }

        authService := user.AuthService
        if authService == "" {
                authService = "native"
        }

        // Get user's primary team for session context
        team, err := a.store.GetPrimaryTeamForUser(user.ID)
        if err != nil {
                a.logger.Warn("User has no team assigned, cannot login", 
                        mlog.String("userID", user.ID),
                        mlog.Err(err))
                return "", errors.New("User is not assigned to any team. Please contact support.")
        }

        session := model.Session{
                ID:          utils.NewID(utils.IDTypeSession),
                Token:       utils.NewID(utils.IDTypeToken),
                UserID:      user.ID,
                AuthService: authService,
                Props:       map[string]interface{}{
                        "team_id": team.ID,
                },
        }
        err = a.store.CreateSession(&session)
        if err != nil {
                return "", errors.Wrap(err, "unable to create session")
        }

        a.metrics.IncrementLoginCount(1)

        a.logger.Info("User logged in successfully", 
                mlog.String("userID", user.ID),
                mlog.String("teamID", team.ID))

        // TODO: MFA verification
        return session.Token, nil
}

// Logout invalidates the user session.
func (a *App) Logout(sessionID string) error {
        err := a.store.DeleteSession(sessionID)
        if err != nil {
                return errors.Wrap(err, "unable to delete the session")
        }

        a.metrics.IncrementLogoutCount(1)

        return nil
}

// RegisterUser creates a new user if the provided data is valid.
func (a *App) RegisterUser(username, email, password string) error {
        var user *model.User
        if username != "" {
                var err error
                user, err = a.store.GetUserByUsername(username)
                if err != nil && !model.IsErrNotFound(err) {
                        return err
                }
                if user != nil {
                        return errors.New("The username already exists")
                }
        }

        if user == nil && email != "" {
                var err error
                user, err = a.store.GetUserByEmail(email)
                if err != nil && !model.IsErrNotFound(err) {
                        return err
                }
                if user != nil {
                        return errors.New("The email already exists")
                }
        }

        // TODO: Move this into the config
        passwordSettings := auth.PasswordSettings{
                MinimumLength: 6,
        }

        err := auth.IsPasswordValid(password, passwordSettings)
        if err != nil {
                return errors.Wrap(err, "Invalid password")
        }

        userID := utils.NewID(utils.IDTypeUser)
        teamID := utils.NewID(utils.IDTypeToken)

        // Create new user
        _, err = a.store.CreateUser(&model.User{
                ID:          userID,
                Username:    username,
                Email:       email,
                Password:    auth.HashPassword(password),
                MfaSecret:   "",
                AuthService: a.config.AuthMode,
                AuthData:    "",
        })
        if err != nil {
                return errors.Wrap(err, "Unable to create the new user")
        }

        // Create new team/organization for this user
        team := &model.Team{
                ID:         teamID,
                Title:      username + "'s Organization",
                ModifiedBy: userID,
                Settings:   map[string]interface{}{},
        }
        _, err = a.store.CreateTeam(team)
        if err != nil {
                a.logger.Error("Failed to create team for new user", mlog.String("userID", userID), mlog.Err(err))
                return errors.Wrap(err, "Unable to create team for user")
        }

        // Add user to their team as owner
        err = a.store.AddUserToTeam(teamID, userID, "owner")
        if err != nil {
                a.logger.Error("Failed to add user to team", mlog.String("userID", userID), mlog.String("teamID", teamID), mlog.Err(err))
                return errors.Wrap(err, "Unable to add user to team")
        }

        a.logger.Info("Created new user with dedicated team", 
                mlog.String("userID", userID), 
                mlog.String("teamID", teamID),
                mlog.String("username", username))

        return nil
}

func (a *App) UpdateUserPassword(username, password string) error {
        err := a.store.UpdateUserPassword(username, auth.HashPassword(password))
        if err != nil {
                return err
        }

        return nil
}

func (a *App) ChangePassword(userID, oldPassword, newPassword string) error {
	var user *model.User
	if userID != "" {
		var err error
		user, err = a.store.GetUserByID(userID)
		if err != nil {
			return errors.Wrap(err, "invalid username or password")
		}
	}

	if user == nil {
		return errors.New("invalid username or password")
	}

	if !auth.ComparePassword(user.Password, oldPassword) {
		a.logger.Debug("Invalid password for user", mlog.String("userID", user.ID))
		return errors.New("invalid username or password")
	}

	err := a.store.UpdateUserPasswordByID(userID, auth.HashPassword(newPassword))
	if err != nil {
		return errors.Wrap(err, "unable to update password")
	}

	return nil
}

// KeycloakLogin authenticates a user via Keycloak SSO.
// It looks up the user by keycloak_sub_id first, then by email.
// If the user doesn't exist, it creates a new user with the provided information.
// Returns the session token, user object, team ID, and any error.
func (a *App) KeycloakLogin(keycloakSubID, email, firstName, lastName string) (string, *model.User, string, error) {
	user, err := a.GetOrCreateKeycloakUser(keycloakSubID, email, firstName, lastName)
	if err != nil {
		a.metrics.IncrementLoginFailCount(1)
		return "", nil, "", errors.Wrap(err, "failed to get or create keycloak user")
	}

	// Get user's primary team for session context
	team, err := a.store.GetPrimaryTeamForUser(user.ID)
	if err != nil {
		a.logger.Warn("User has no team assigned, cannot login",
			mlog.String("userID", user.ID),
			mlog.Err(err))
		return "", nil, "", errors.New("User is not assigned to any team. Please contact support.")
	}

	// Create session
	session := model.Session{
		ID:          utils.NewID(utils.IDTypeSession),
		Token:       utils.NewID(utils.IDTypeToken),
		UserID:      user.ID,
		AuthService: "keycloak",
		Props: map[string]interface{}{
			"team_id":         team.ID,
			"keycloak_sub_id": keycloakSubID,
		},
	}

	err = a.store.CreateSession(&session)
	if err != nil {
		return "", nil, "", errors.Wrap(err, "unable to create session")
	}

	a.metrics.IncrementLoginCount(1)

	a.logger.Info("User logged in via Keycloak",
		mlog.String("userID", user.ID),
		mlog.String("teamID", team.ID),
		mlog.String("keycloakSubID", keycloakSubID))

	return session.Token, user, team.ID, nil
}

// GetOrCreateKeycloakUser finds an existing user by Keycloak subject ID or email,
// or creates a new user if one doesn't exist.
// This follows the requirement that subsequent authentication should be based on
// the Keycloak sub ID, so if the email changes in Keycloak, the user can still be authenticated.
func (a *App) GetOrCreateKeycloakUser(keycloakSubID, email, firstName, lastName string) (*model.User, error) {
	// First, try to find user by Keycloak subject ID (preferred for returning users)
	user, err := a.store.GetUserByKeycloakSubID(keycloakSubID)
	if err == nil && user != nil {
		a.logger.Debug("Found user by Keycloak sub ID",
			mlog.String("userID", user.ID),
			mlog.String("keycloakSubID", keycloakSubID))
		return user, nil
	}

	// If not found by sub ID, try to find by email (for first-time Keycloak login)
	if model.IsErrNotFound(err) || user == nil {
		user, err = a.store.GetUserByEmail(email)
		if err == nil && user != nil {
			// Found user by email, update their keycloak_sub_id for future logins
			a.logger.Info("Found existing user by email, linking to Keycloak",
				mlog.String("userID", user.ID),
				mlog.String("email", email),
				mlog.String("keycloakSubID", keycloakSubID))

			user.KeycloakSubID = keycloakSubID
			user.AuthService = "keycloak"
			updatedUser, updateErr := a.store.UpdateUser(user)
			if updateErr != nil {
				a.logger.Error("Failed to update user with Keycloak sub ID",
					mlog.String("userID", user.ID),
					mlog.Err(updateErr))
				// Continue with the existing user even if update fails
				return user, nil
			}
			return updatedUser, nil
		}
	}

	// User doesn't exist - create a new one
	a.logger.Info("Creating new user from Keycloak",
		mlog.String("email", email),
		mlog.String("keycloakSubID", keycloakSubID))

	userID := utils.NewID(utils.IDTypeUser)
	teamID := utils.NewID(utils.IDTypeToken)

	// Generate a username from email or name
	username := email
	if firstName != "" || lastName != "" {
		username = strings.TrimSpace(firstName + " " + lastName)
		if username == "" {
			username = email
		}
	}

	// Create new user
	newUser := &model.User{
		ID:            userID,
		Username:      username,
		Email:         email,
		FirstName:     firstName,
		LastName:      lastName,
		Password:      "", // No password for Keycloak users
		MfaSecret:     "",
		AuthService:   "keycloak",
		AuthData:      keycloakSubID,
		KeycloakSubID: keycloakSubID,
	}

	createdUser, err := a.store.CreateUser(newUser)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create new user")
	}

	// Create new team/organization for this user
	team := &model.Team{
		ID:         teamID,
		Title:      username + "'s Organization",
		ModifiedBy: userID,
		Settings:   map[string]interface{}{},
	}
	_, err = a.store.CreateTeam(team)
	if err != nil {
		a.logger.Error("Failed to create team for new Keycloak user",
			mlog.String("userID", userID),
			mlog.Err(err))
		return nil, errors.Wrap(err, "unable to create team for user")
	}

	// Add user to their team as owner
	err = a.store.AddUserToTeam(teamID, userID, "owner")
	if err != nil {
		a.logger.Error("Failed to add Keycloak user to team",
			mlog.String("userID", userID),
			mlog.String("teamID", teamID),
			mlog.Err(err))
		return nil, errors.Wrap(err, "unable to add user to team")
	}

	a.logger.Info("Created new Keycloak user with dedicated team",
		mlog.String("userID", userID),
		mlog.String("teamID", teamID),
		mlog.String("email", email),
		mlog.String("keycloakSubID", keycloakSubID))

	return createdUser, nil
}
