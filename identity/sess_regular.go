package identity

import (
	"context"
	"errors"
	"fmt"
)


func (sess *Session) regularStart(ctx context.Context, ver *VerifierSummary, auth *Authentication, args M, identityName, identity string) (M, error) {
	if ver.IdentityName != identityName {
		panic("shit happened")
	}

	idn := ver.Identity.Identity

	identity, err := idn.NormalizeAndValidateIdentity(identity)
	if err != nil {
		return nil, err
	}

	stage := &AuthenticationStage{
		Completed:          false,
		UserID:             "",
		VerifierName:       ver.Name,
		IdentityName:       identityName, // FIXME
		Identity:           identity,
		StoredSecurityCode: "",
		InputSecurityCode:  "",
		OAuth2State:        "",
		VerifierData:       nil, //> later
	}

	{
		user, err := sess.manager.backend.GetUserByIdentity(ctx, identityName, identity)
		if err != nil {
			return nil, err
		}
		if user != nil {
			stage.UserID = user.ID
		}

		switch auth.Objective {
		case ObjectiveSignIn:
			if stage.UserID == "" {
				return nil, ErrIdentityNotRegistered
			}
		case ObjectiveSignUp:
			if stage.UserID != "" {
				return nil, errors.New("identity already registered")
			}
		case ObjectiveAttach:
			if stage.UserID != "" && stage.UserID != auth.UserID {
				return nil, ErrAlreadyRegistered
			}
			if stage.UserID != "" && stage.UserID == auth.UserID {
				return nil, ErrAlreadyAttached
			}
		}
	}

	stage.StoredSecurityCode, err = ver.internal.regularRef.StartRegularVerification(ctx, identity, VerifierData{})
	if err != nil {
		return nil, err
	}

	auth.addStage(stage)

	return M{}, nil
}

func (sess *Session) regularVerify(ctx context.Context, ver *VerifierSummary, auth *Authentication, inputCode, identityName, identity string) (error) {
	if ver.IdentityName != identityName {
		panic("shit happened")
	}

	idn := ver.Identity.Identity

	identity, err := idn.NormalizeAndValidateIdentity(identity)
	if err != nil {
		return err
	}

	switch auth.Objective {
	case ObjectiveSignIn:
		var user *User
		if auth.UserID != "" {
			user, err = sess.manager.backend.GetUser(ctx, auth.UserID)
		} else {
			user, err = sess.manager.backend.GetUserByIdentity(ctx, idn.Info().Name, identity)
			if user == nil {
				panic(fmt.Sprintf("bullshit %s %s", idn.Info().Name, identity))
			}
		}
		if err != nil {
			return err
		}
		if user == nil {
			return ErrUserNotFound
		}
		auth.UserID = user.ID
	}

	stage := auth.findStage(ver.Name, identity)

	stage.InputSecurityCode = inputCode
	if stage.InputSecurityCode == stage.StoredSecurityCode {
		stage.Completed = true
		return nil
	} else {
		stage.Completed = false
		return ErrVerificationCodeMismatch
	}
}
