package identity

import "github.com/rs/xid"

func (sess *Session) handleAuthentication(auth *Authentication) error {
	var (
		user *User
		err  error
	)

	switch auth.Objective {
	case ObjectiveSignIn:
		user, err = sess.manager.backend.GetUser(auth.UserID)
	case ObjectiveSignUp:
		user = &User{
			ID:                xid.New().String(),
			Version:           1,
			AuthFactorsNumber: 1,
		}
	case ObjectiveAttach:
		user, err = sess.manager.backend.GetUser(auth.UserID)
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
			user.add(stage.VerifierData, stage.IdentityData)
		case ObjectiveAttach:
			user.add(stage.VerifierData, stage.IdentityData)
		}
	}

	if err := sess.manager.backend.SaveAuthentication(auth); err != nil {
		panic(err)
	}

	if completedCount >= auth.RequiredFactorsCount {
		// TODO Save user
		if err := sess.manager.backend.SaveUser(user); err != nil {
			return err
		}

		// FIXME
		// TODO Authenticate session
		if err := sess.sess.SetUser(user.ID); err != nil {
			return err
		}
		sess.become(user.ID)
	}

	return nil
}
