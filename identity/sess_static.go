package identity

import (
	"context"
	"errors"
)

func (sess *Session) staticStart(ctx context.Context, ver *VerifierSummary, auth *Authentication, args M, identityName, identity string) (M, error) {
	stage := &AuthenticationStage{
		Completed:          false,
		UserID:             "",
		VerifierName:       ver.Name,
		IdentityName:       identityName,
		StoredSecurityCode: "",  //> noop
		InputSecurityCode:  "",  //> noop
		OAuth2State:        "",  //> noop
		VerifierData:       nil, //> later
	}

	if identityName != "" {
		if user, err := sess.manager.backend.GetUserByIdentity(ctx, identityName, identity); err != nil {
			return nil, err
		} else if user != nil {
			return nil, errors.New("user with such identity already exists")
		}

		stage.IdentityName = identityName
		stage.Identity = identity
	}

	verifierData := &VerifierData{
		Name: ver.Name,
	}
	res, err := ver.internal.staticRef.InitStaticVerifier(ctx, verifierData, args)
	if err != nil {
		return nil, err
	}
	stage.VerifierData = verifierData

	switch auth.Objective {
	case ObjectiveSignIn:
		panic("start() could not be called on static verifier during signin")
	case ObjectiveSignUp: //> Template to construct new user on successful authentication
		if sess.cookie.GetUserID() != "" {
			return nil, errors.New("should not be authenticated")
		}
		if auth.UserID != "" {
			panic("shit happened")
		}

		{ // FIXME !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			//> Forbid non-standalone identities
			if identityName != "" && !sess.manager.identities[identityName].Standalone {
				return nil, errors.New("could not combine static verifier and non-standalone identity in same stage")
			}
		}

		auth.addStage(stage)

		return res, nil
	case ObjectiveAttach: //> Add new verifier to existing user
		if sess.cookie.GetUserID() == "" {
			return nil, errors.New("not authenticated")
		}

		auth.addStage(stage)

		return res, nil
	}

	panic("shit happened")
}

func (sess *Session) staticVerify(ctx context.Context, ver *VerifierSummary, auth *Authentication, inputCode, identityName, identity string) error {
	switch auth.Objective {
	case ObjectiveSignIn:
		var (
			user *User
			err  error
		)
		if auth.UserID != "" {
			user, err = sess.manager.backend.GetUser(ctx, auth.UserID)
		} else {
			user, err = sess.manager.backend.GetUserByIdentity(ctx, identityName, identity)
		}
		if err != nil {
			return err
		}
		if user == nil {
			return errors.New("user not found")
		}
		auth.UserID = user.ID

		verifierData := user.findVerifierData(ver.Name, "")
		if verifierData == nil {
			return errors.New("no verifier data for this verifier and user")
		}

		if err := ver.internal.staticRef.StaticVerify(ctx, *verifierData, inputCode); err != nil {
			return err
		}

		stage := &AuthenticationStage{
			Completed:          true,
			UserID:             "",
			VerifierName:       ver.Name,
			IdentityName:       "",
			Identity:           "",
			StoredSecurityCode: "", //> noop
			InputSecurityCode:  "", //> noop
			OAuth2State:        "",
			VerifierData:       nil, //> later
		}

		auth.addStage(stage)

		return nil
	case ObjectiveSignUp, ObjectiveAttach:
		stage := auth.findStage(ver.Name, "")

		if err := ver.internal.staticRef.StaticVerify(ctx, *stage.VerifierData, inputCode); err != nil {
			return err
		}

		stage.Completed = true
		return nil
	}
	panic("shit happened")
}
