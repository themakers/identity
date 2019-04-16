package identity

import (
	"context"
	"google.golang.org/grpc/metadata"
)

func (sess *Session) InitializeStaticVerifier(ctx context.Context, data *VerifierData) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ErrAuthenticationForSessionAlreadyExist
	}
	token := md[SessionTokenName][0]
	auth, err := sess.manager.backend.GetAuthenticationBySessionToken(token)
	if err != nil {
		panic(err)
	}

	_, err = sess.manager.backend.AddUserAuthenticationData(auth.UserID, data)
	if err != nil {
		return err
	} else {
		return nil
	}

}