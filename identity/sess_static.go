package identity

import (
	"context"
	"google.golang.org/grpc/metadata"
	"log"
)

func (sess *Session) StartStaticVerification(ctx context.Context, vd VerifierData) (AuthenticationID string, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		panic(ok)
	}
	vername := vd.VerifierName
	AID := md[SessionTokenName][0]
	p := sess.manager.ver[vername].internal.staticRef
	log.Println("Static VERIFIER", sess.manager.ver[vername], p, p.Info().Name)
	var user *User
	var login, password string
	for login, password = range vd.AuthenticationData {
		user, err = sess.manager.backend.GetUserByLogin(login)
		if err != nil {
			panic(err)
		}
		if user != nil {
			break
		}
	}
	if user == nil {
		panic(err)
	}
	for _, e := range user.Verifiers {
		if e.VerifierName == vername {
			err = p.StartStaticVerification(ctx, e.AuthenticationData[login], password, login)
			break
		}
	}
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddUserToAuthentication(AID, user.ID)
	if err != nil {
		panic(err)
	}

	return AID, err
}

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

}
