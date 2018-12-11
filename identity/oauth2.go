package identity

import (
	"context"
)

func (sess *Session) OAuth2Verify(ctx context.Context, prov, code string) (err error) {
	p := sess.manager.prov[prov].internal.oauth2Ref
	token, err := p.HandleOAuth2Callback(ctx, code)
	if err != nil {
		return err
	}

	identity, err := p.GetOAuth2Identity(ctx, token.AccessToken)
	if err != nil {
		return err
	}

	if err := sess.handleIncomingIdentity(ctx, identity); err != nil {
		return err
	}

	return nil
}
