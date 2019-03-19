package identity

import (
	"context"
	"golang.org/x/oauth2"
)



type VerifierInfo struct {
	Name         string
	IdentityName string
}

type Verifier interface {
	Info() VerifierInfo
}

type RegularVerification interface {
	Verifier

	StartType2Verification(ctx context.Context, identity string) (securityCode string, iden *Identity, err error)
	RegularVerification(ctx context.Context, verificationID, securitycode string)
}

type ReverseVerification interface {
	Verifier

	StartReverseVerification(ctx context.Context) (target, securityCode string, err error)
}

type OAuth2Verification interface {
	Verifier

	GetOAuth2URL(code string) string
	HandleOAuth2Callback(ctx context.Context, code string) (token *oauth2.Token, err error)
	GetOAuth2Identity(ctx context.Context, accessToken string) (identity *Identity, err error)
}

type StaticVerification interface {
	Verifier

	StartStaticVerification(ctx context.Context) ()

}