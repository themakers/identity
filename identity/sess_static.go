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
	for k, v := range vd.AuthenticationData {
		user, err := sess.manager.backend.GetUserByLogin(k)
	}
	if err != nil {
		panic(err)
	}
	securitycode, err := p.StartStaticVerification(ctx, idn, vd)
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddTempAuthDataToAuth(AID, map[string]string{vername: securitycode})
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddUserToAuthentication(AID, user.ID)
	if err != nil {
		panic(err)
	}

	return AID, err
}

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
