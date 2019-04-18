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

	StartRegularVerification(ctx context.Context, identity string, verifierData VerifierData) (securityCode string, err error)
}

type ReverseVerification interface {
	Verifier

	StartReverseVerification(ctx context.Context) (target, securityCode string, err error)
}

type OAuth2Verification interface {
	Verifier

	GetOAuth2URL(code string) string
	HandleOAuth2Callback(ctx context.Context, code string) (token *oauth2.Token, err error)
	GetOAuth2Identity(ctx context.Context, accessToken string) (identity *IdentityData, err error)
}

type StaticVerification interface {
	Verifier

	StartStaticVerification(ctx context.Context, login string, password string) (iden *VerifierData, err error)
}
