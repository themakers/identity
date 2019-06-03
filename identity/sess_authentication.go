package identity

import (
	"context"
)

type Status struct {
	Token string

	Authenticating *StatusAuthenticating
	Authenticated  *StatusAuthenticated
}
type StatusAuthenticating struct {
	Objective        AuthenticationObjective
	RemainingFactors int
	CompletedFactors []StatusCompletedFactors
}
type StatusCompletedFactors struct {
	VerifierName string
	IdentityName string
	Identity     string
}
type StatusAuthenticated struct {
	User string
}

func (sess *Session) CheckStatus(ctx context.Context) (Status, error) {
	status := Status{
		Token:          sess.token,
		Authenticating: nil,
		Authenticated: nil,
	}

	if sess.user != "" {
		status.Authenticated = &StatusAuthenticated{
			User: sess.user,
		}
	}

	auth, err := sess.manager.backend.GetAuthentication(ctx, sess.token)
	if err != nil {
		return Status{}, err
	}
	if auth != nil {
		status.Authenticating = auth.status()
	}
	return status, nil
}

func (sess *Session) StartAuthentication(ctx context.Context, objective AuthenticationObjective) error {
	_, err := sess.manager.backend.CreateAuthentication(ctx, sess.token, objective, sess.user)
	return err
}

func (sess *Session) CancelAuthentication(ctx context.Context) error {
	return sess.manager.backend.RemoveAuthentication(ctx, sess.token)
}

// FIXME Why IdentityData??? Not summary???
func (sess *Session) ListMyIdentitiesAndVerifiers(ctx context.Context) (idn []IdentityData, ver []VerifierSummary, err error) {
	userID := sess.user

	var user *User
	if userID == "" {
		auth, err := sess.manager.backend.GetAuthentication(ctx, sess.token)
		if err != nil {
			return nil, nil, err
		}
		userID = auth.UserID
	}

	if userID == "" {
		return nil, nil, nil
	}

	user, err = sess.manager.backend.GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	// TODO: Review code below

	for _, uiden := range user.Identities {
		idn = append(idn, IdentityData{Name: uiden.Name, Identity: uiden.Identity})
	}

	for _, v := range user.Verifiers {
		ver = append(ver, *sess.manager.verifiers[v.Name])
	}

	return
}

func (sess *Session) ListSupportedIdentitiesAndVerifiers() (idn []IdentitySummary, ver []VerifierSummary, err error) {
	// TODO: Review code below

	for _, i := range sess.manager.identities {
		idn = append(idn, *i)
	}

	for _, v := range sess.manager.verifiers {
		ver = append(ver, *v)
	}

	return idn, ver, nil
}
