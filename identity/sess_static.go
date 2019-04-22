package identity

import (
	"context"
	"google.golang.org/grpc/metadata"
)

func (sess *Session) InitializeStaticVerifier(ctx context.Context, initdata map[string]string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ErrAuthenticationForSessionAlreadyExist
	}
	token := md[SessionTokenName][0]
	auth, err := sess.manager.backend.GetAuthenticationBySessionToken(token)
	if err != nil {
		panic(err)
	}
	if auth.UserID == "" {
		//todo: create new user with initialization data
	}
	return nil
}
