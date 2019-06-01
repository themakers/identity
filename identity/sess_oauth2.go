package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

func (sess *Session) oauth2Start(ctx context.Context, ver *VerifierSummary, auth *Authentication, args M, identityName, identity string) (M, error) {
	switch auth.Objective {
	case ObjectiveSignIn, ObjectiveSignUp, ObjectiveAttach:
		state := randomOAuth2State()
		redirectURL := ver.internal.oauth2Ref.GetOAuth2URL(state)

		stage := &AuthenticationStage{
			Completed:          false,
			UserID:             "",
			VerifierName:       ver.Name,
			IdentityName:       ver.Name, // FIXME
			Identity:           "",
			StoredSecurityCode: "", //> noop
			InputSecurityCode:  "", //> noop
			OAuth2State:        state,
			VerifierData:       nil, //> later
		}

		auth.Stages = append(auth.Stages, stage)

		return M{
			"redirect_url": redirectURL,
		}, nil
	}

	panic("shit happened")
}

func (sess *Session) oauth2Verify(ctx context.Context, ver *VerifierSummary, auth *Authentication, inputCode, identityName, identity string) (bool, error) {
	// FIXME Check CSRF code

	token, err := ver.internal.oauth2Ref.HandleOAuth2Callback(ctx, inputCode)
	if err != nil {
		return false, err
	}

	identityData, verifierData, err := ver.internal.oauth2Ref.GetOAuth2Identity(ctx, token.AccessToken)
	if err != nil {
		return false, err
	}

	stage := auth.findStage(ver.Name, ver.Name)

	stage.IdentityName = identityData.Name
	stage.Identity = identityData.Identity
	stage.VerifierData = verifierData

	user, err := sess.manager.backend.GetUserByIdentity(ctx, stage.IdentityName, stage.Identity)
	if err != nil {
		return false, err
	}

	if user != nil {
		stage.UserID = user.ID
	}

	switch auth.Objective {
	case ObjectiveSignIn:
		if stage.UserID == "" {
			return false, errors.New("no such user")
		}
		stage.Completed = true
		return true, nil
	case ObjectiveSignUp:
		if stage.UserID != "" {
			return false, errors.New("already")
		}
		stage.Completed = true
		return true, nil
	case ObjectiveAttach:
		if stage.UserID != "" && stage.UserID != auth.UserID {
			return false, errors.New("different user")
		}
		if stage.UserID != "" && stage.UserID == auth.UserID {
			return false, errors.New("already attached")
		}
		stage.Completed = true
		return true, nil
	}
	panic("shit happened")
}

func randomOAuth2State() string {
	b := [8]byte{}
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
