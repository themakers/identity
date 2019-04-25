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
