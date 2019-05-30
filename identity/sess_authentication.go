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
}
type StatusAuthenticated struct {
	User string
}

func (sess *Session) CheckStatus(ctx context.Context) (Status, error) {
	if sess.user != "" {
		return Status{
			Token:          sess.token,
			Authenticating: nil,
			Authenticated: &StatusAuthenticated{
				User: sess.user,
			},
		}, nil
	}

	auth, err := sess.manager.backend.GetAuthentication(ctx, sess.token)
	if err != nil {
		return Status{}, err
	}
	if auth == nil {
		return Status{
			Token:          sess.token,
			Authenticating: nil,
			Authenticated:  nil,
		}, nil
	} else {
		return Status{
			Token: sess.token,
			Authenticating: &StatusAuthenticating{
				Objective:        auth.Objective,
				RemainingFactors: auth.RequiredFactorsCount, // FIXME !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			},
			Authenticated: nil,
		}, nil
	}
}

func (sess *Session) StartAuthentication(ctx context.Context, objective AuthenticationObjective) error {
	_, err := sess.manager.backend.CreateAuthentication(ctx, sess.token, objective, sess.user)
	return err
}

// FIXME Why IdentityData??? Not summary???
func (sess *Session) ListMyIdentitiesAndVerifiers(ctx context.Context) (idn []IdentityData, ver []VerifierSummary, err  error) {
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
		ver = append(ver, *sess.manager.verifiers[v.VerifierName])
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
