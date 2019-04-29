package identity

import (
	"context"
	"errors"
	"google.golang.org/grpc/metadata"
)

func (sess *Session) CheckStatus(ctx context.Context) (int, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0, errors.New("False")
	}
	AID := md[SessionTokenName][0]
	auth, err := sess.manager.backend.GetAuthenticationBySessionToken(AID)
	if err != nil {
		panic(err)
	}
	toAuth := auth.FactorsCount
	for _, value := range auth.FactorsStatus {
		if value {
			toAuth--
		}
	}
	return toAuth, nil
}

func (sess *Session) StartAuthentication(ctx context.Context, vname string) (res bool, err error) {
	token := getIncomingSessionToken(ctx)
	_, err = sess.manager.backend.CreateAuthentication(token, vname)
	if err != nil && err != ErrAuthenticationForSessionAlreadyExist {
		return false, err
	}
	if err == ErrAuthenticationForSessionAlreadyExist {
		return true, nil
	}
	return true, nil
}

func (sess *Session) ListMyIdentitiesAndVerifiers(ctx context.Context) (idn []IdentityData, ver []VerifierSummary) {
	token := getIncomingSessionToken(ctx)
	auth, err := sess.manager.backend.GetAuthenticationBySessionToken(token)
	if err != nil {
		panic(err)
	}
	user, err := sess.manager.backend.GetUserByID(auth.UserID)
	if err != nil {
		return nil, nil
	}
	for _, uiden := range user.Identities {
		idn = append(idn, IdentityData{Name: uiden.Name,
			Identity: uiden.Identity})
		for _, v := range user.Verifiers {
			ver = append(ver, sess.manager.ver[v.VerifierName])
		}
	}
	return idn, ver
}

func (sess *Session) ListAllIndentitiesAndVerifiers() (idn []IdentityData, ver []VerifierSummary) {

	for _, v := range sess.manager.verifiers {
		ver = append(ver, sess.manager.ver[v.Info().Name])
	}
	for _, i := range sess.manager.identities {
		idn = append(idn, IdentityData{Name: i.Info().Name,
			Identity: i.Info().Name})
	}
	return idn, ver
}
