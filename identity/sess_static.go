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
	v := sess.manager.ver[vername].internal.staticRef
	log.Println("Static VERIFIER", sess.manager.ver[vername], v, v.Info().Name)
	var user *User
	var login, password string
	for login, password = range vd.AuthenticationData {
		user, err = sess.manager.backend.GetUserByLogin(login, vername)
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
	var check bool
	for _, e := range user.Verifiers {
		if e.VerifierName == vername {
			check = v.StartStaticVerification(ctx, e.AuthenticationData[login], password, login)
			break
		}
	}
	if !check {
		panic(err)
	}
	_, err = sess.manager.backend.AddUserToAuthentication(AID, user.ID)
	if err != nil {
		panic(err)
	}

	return AID, err
}

func (sess *Session) InitializeStaticVerifier(ctx context.Context, idn IdentityData, vd VerifierData) error {
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
		_ = sess.handleIncomingIdentity(ctx, &idn, &vd)
	} else {
		_, err = sess.manager.backend.AddUserAuthenticationData(auth.UserID, &vd)
		if err != nil {
			panic(err)
		}
	}
	return nil
}
