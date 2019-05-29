package identity

import (
	"context"
	"errors"
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
		StoredSecurityCode: "",
		InputSecurityCode:  "",
		OAuth2State:        "",
		IdentityData: &IdentityData{
			Name:     identityName,
			Identity: identity,
		}, //> maybe later
		VerifierData: nil, //> later
	}

	{
		user, err := sess.manager.backend.GetUserByIdentity(identityName, identity)
		if err != nil {
			return nil, err
		}
		if user != nil {
			stage.UserID = user.ID
		}

		switch auth.Objective {
		case ObjectiveSignIn:
			if stage.UserID == "" {
				return nil, errors.New("identity not registered")
			}
		case ObjectiveSignUp:
			if stage.UserID != "" {
				return nil, errors.New("identity already registered")
			}
		case ObjectiveAttach:
			if stage.UserID != "" && stage.UserID != auth.UserID {
				return nil, errors.New("different user")
			}
			if stage.UserID != "" && stage.UserID == auth.UserID {
				return nil, errors.New("already attached")
			}
		}
	}

	stage.StoredSecurityCode, err = ver.internal.regularRef.StartRegularVerification(ctx, identity, VerifierData{})
	if err != nil {
		return nil, err
	}

	auth.Stages = append(auth.Stages, stage)

	return M{}, nil
}

func (sess *Session) regularVerify(ctx context.Context, ver *VerifierSummary, auth *Authentication, inputCode, identityName, identity string) (bool, error) {
	if ver.IdentityName != identityName {
		panic("shit happened")
	}

	idn := ver.Identity.Identity

	identity, err := idn.NormalizeAndValidateIdentity(identity)
	if err != nil {
		return false, err
	}

	stage := auth.findStage(ver.Name, identity)

	stage.InputSecurityCode = inputCode
	if stage.InputSecurityCode == stage.StoredSecurityCode {
		stage.Completed = true
		return true, nil
	} else {
		stage.Completed = false
		return false, nil
	}
}
