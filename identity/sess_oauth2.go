package identity

import (
	"context"
	"google.golang.org/grpc/metadata"
)

func (sess *Session) OAuth2Verify(ctx context.Context, ver, code string) (err error) {
	p := sess.manager.ver[ver].internal.oauth2Ref

	token, err := p.HandleOAuth2Callback(ctx, code)
	if err != nil {
		return err
	}

	identity, vd, err := p.GetOAuth2Identity(ctx, token.AccessToken)
	if err != nil {
		return err
	}

	if err := sess.handleIncomingIdentity(ctx, identity, vd); err != nil {
		return err
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		panic(ok)
	}
	AID := md[SessionTokenName][0]
	user, err := sess.manager.backend.GetUserByIdentity(identity.Identity)
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddUserToAuthentication(AID, user.ID)
	if err != nil {
		panic(err)
	}
	err = sess.manager.backend.UpdateFactorStatus(AID, ver)
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddUserAuthenticationData(user.ID, vd)
	// todo: realize saving additional data to user
	return nil
}
