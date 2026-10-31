package app

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/mattermost/focalboard/server/model"
	"github.com/stretchr/testify/require"
)

func keycloakMember() *model.User {
	return &model.User{
		ID:            "member-1",
		Username:      "old@example.com",
		Email:         "old@example.com",
		AuthService:   "keycloak",
		KeycloakSubID: "sub-1",
	}
}

func confirmWith(email string, verified bool, err error) (KeycloakEmailConfirmer, *int) {
	calls := 0
	return func() (string, bool, error) {
		calls++
		return email, verified, err
	}, &calls
}

func TestGetOrCreateKeycloakUserEmailSync(t *testing.T) {
	t.Run("a returning member whose verified Keycloak email changed gets the new email", func(t *testing.T) {
		th, tearDown := SetupTestHelper(t)
		defer tearDown()
		th.Store.EXPECT().GetUserByKeycloakSubID("sub-1").Return(keycloakMember(), nil)
		th.Store.EXPECT().GetUserByEmail("new@example.com").Return(nil, model.NewErrNotFound("user"))
		th.Store.EXPECT().GetUserByUsername("new@example.com").Return(nil, model.NewErrNotFound("user"))
		th.Store.EXPECT().UpdateUser(gomock.Any()).DoAndReturn(func(u *model.User) (*model.User, error) {
			require.Equal(t, "member-1", u.ID)
			require.Equal(t, "new@example.com", u.Email)
			require.Equal(t, "new@example.com", u.Username)
			require.Equal(t, "sub-1", u.KeycloakSubID)
			return u, nil
		})
		confirm, _ := confirmWith("new@example.com", true, nil)

		user, err := th.App.GetOrCreateKeycloakUser("sub-1", "New@Example.com", "", "", confirm)
		require.NoError(t, err)
		require.Equal(t, "member-1", user.ID)
		require.Equal(t, "new@example.com", user.Email)
	})

	t.Run("a custom username is kept when the email changes", func(t *testing.T) {
		th, tearDown := SetupTestHelper(t)
		defer tearDown()
		member := keycloakMember()
		member.Username = "Member Name"
		th.Store.EXPECT().GetUserByKeycloakSubID("sub-1").Return(member, nil)
		th.Store.EXPECT().GetUserByEmail("new@example.com").Return(nil, model.NewErrNotFound("user"))
		th.Store.EXPECT().UpdateUser(gomock.Any()).DoAndReturn(func(u *model.User) (*model.User, error) {
			require.Equal(t, "Member Name", u.Username)
			return u, nil
		})
		confirm, _ := confirmWith("new@example.com", true, nil)

		user, err := th.App.GetOrCreateKeycloakUser("sub-1", "new@example.com", "", "", confirm)
		require.NoError(t, err)
		require.Equal(t, "new@example.com", user.Email)
	})

	t.Run("an unchanged email (any case) does not call Keycloak or write", func(t *testing.T) {
		th, tearDown := SetupTestHelper(t)
		defer tearDown()
		th.Store.EXPECT().GetUserByKeycloakSubID("sub-1").Return(keycloakMember(), nil)
		confirm, calls := confirmWith("old@example.com", true, nil)

		user, err := th.App.GetOrCreateKeycloakUser("sub-1", "OLD@example.com", "", "", confirm)
		require.NoError(t, err)
		require.Equal(t, "old@example.com", user.Email)
		require.Equal(t, 0, *calls)
	})

	for _, tc := range []struct {
		name     string
		email    string
		verified bool
		err      error
	}{
		{"an unverified Keycloak email never replaces the stored email", "new@example.com", false, nil},
		{"an email Keycloak does not confirm for this token is ignored", "someone@example.com", true, nil},
		{"a Keycloak outage keeps the stored email", "", false, errors.New("timeout")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			th, tearDown := SetupTestHelper(t)
			defer tearDown()
			th.Store.EXPECT().GetUserByKeycloakSubID("sub-1").Return(keycloakMember(), nil)
			confirm, calls := confirmWith(tc.email, tc.verified, tc.err)

			user, err := th.App.GetOrCreateKeycloakUser("sub-1", "new@example.com", "", "", confirm)
			require.NoError(t, err)
			require.Equal(t, "old@example.com", user.Email)
			require.Equal(t, 1, *calls)
		})
	}

	t.Run("the stored email is kept when another user already has the new address", func(t *testing.T) {
		th, tearDown := SetupTestHelper(t)
		defer tearDown()
		th.Store.EXPECT().GetUserByKeycloakSubID("sub-1").Return(keycloakMember(), nil)
		th.Store.EXPECT().GetUserByEmail("new@example.com").Return(&model.User{ID: "someone-else", Email: "new@example.com"}, nil)
		confirm, _ := confirmWith("new@example.com", true, nil)

		user, err := th.App.GetOrCreateKeycloakUser("sub-1", "new@example.com", "", "", confirm)
		require.NoError(t, err)
		require.Equal(t, "member-1", user.ID)
		require.Equal(t, "old@example.com", user.Email)
	})

	t.Run("a failed email write does not block sign-in", func(t *testing.T) {
		th, tearDown := SetupTestHelper(t)
		defer tearDown()
		th.Store.EXPECT().GetUserByKeycloakSubID("sub-1").Return(keycloakMember(), nil)
		th.Store.EXPECT().GetUserByEmail("new@example.com").Return(nil, model.NewErrNotFound("user"))
		th.Store.EXPECT().GetUserByUsername("new@example.com").Return(nil, model.NewErrNotFound("user"))
		th.Store.EXPECT().UpdateUser(gomock.Any()).Return(nil, errors.New("duplicate key"))
		confirm, _ := confirmWith("new@example.com", true, nil)

		user, err := th.App.GetOrCreateKeycloakUser("sub-1", "new@example.com", "", "", confirm)
		require.NoError(t, err)
		require.Equal(t, "old@example.com", user.Email)
	})
}
