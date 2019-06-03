package identity

import (
	"context"
	"github.com/rs/xid"
)

func (sess *Session) handleAuthentication(ctx context.Context, auth *Authentication) error {
	var (
		user *User
		err  error
	)

	switch auth.Objective {
	case ObjectiveSignIn:
		user, err = sess.manager.backend.GetUser(ctx, auth.UserID)
	case ObjectiveSignUp:
		user = &User{
			ID:                xid.New().String(),
			AuthFactorsNumber: 1,
		}
	case ObjectiveAttach:
		user, err = sess.manager.backend.GetUser(ctx, auth.UserID)
	}
	if err != nil {
		return err
	}

	if auth.Objective == ObjectiveAttach {
		auth.RequiredFactorsCount = 1
	} else if user != nil {
		auth.RequiredFactorsCount = user.AuthFactorsNumber
	}

	completedCount := 0

	for _, stage := range auth.Stages {
		if stage.Completed {
			completedCount++
		} else {
			continue
		}

		switch auth.Objective {
		case ObjectiveSignIn:
		case ObjectiveSignUp:
			user.add(stage.VerifierData, &IdentityData{
				Name:     stage.IdentityName,
				Identity: stage.Identity,
			})
		case ObjectiveAttach:
			user.add(stage.VerifierData, &IdentityData{
				Name:     stage.IdentityName,
				Identity: stage.Identity,
			})
		}
	}

	auth, err = sess.manager.backend.SaveAuthentication(ctx, auth)
	if err != nil {
		panic(err)
	}

	if completedCount >= auth.RequiredFactorsCount {
		// TODO Save user
		if user.Version == 0 {
			user, err = sess.manager.backend.CreateUser(ctx, user)
			if err != nil {
				return err
			}
		} else {
			user, err = sess.manager.backend.SaveUser(ctx, user)
			if err != nil {
				return err
			}
		}

		// FIXME
		// TODO Authenticate session
		if err := sess.sess.SetUser(user.ID); err != nil {
			return err
		}
		sess.become(user.ID)

		if err := sess.manager.backend.RemoveAuthentication(ctx, auth.ID); err != nil {
			return err
		}
	}

	return nil
}
