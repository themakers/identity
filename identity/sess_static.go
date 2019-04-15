package identity

import (
	"context"
	"google.golang.org/grpc/metadata"
	"log"
)

func (sess *Session) StartStaticVerification(ctx context.Context, vername, login string, password string) (AuthenticationID string, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		panic(ok)
	}
	AID := md[SessionTokenName][0]
	p := sess.manager.ver[vername].internal.staticRef
	log.Println("Static VERIFIER", sess.manager.ver[vername], p, p.Info().Name)
	login, err = sess.manager.idn[p.Info().IdentityName].NormalizeAndValidateData(login)

	_ = sess.handleIncomingIdentity(ctx, &IdentityData{Identity: login, Name: p.Info().IdentityName})
	user, err := sess.manager.backend.GetUserByLogin(login)
	if err != nil {
		panic(err)
	}
	data, err := p.StartStaticVerification(ctx, login, user.Identities[0].Identity)
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddUserAuthenticationData(user.ID, data)
	if err != nil {
		panic(err)
	}
	return AID, err
}
