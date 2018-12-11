package identity

import (
	"context"
	"golang.org/x/oauth2"
)

type ProviderInfo struct {
	Name string
}

type Type1Event struct {
	Identity     *Identity
	SecurityCode string
}

type VerificationError struct {
	Code    string
	Details map[string]string
}

func (ve *VerificationError) Error() string {
	return ""
}

type Provider interface {
	Info() ProviderInfo

	// Must be idempotent
	NormalizeIdentity(idn string) string
}

type Type1Provider interface {
	Provider

	// identity - optional
	StartType1Verification(ctx context.Context) (target, securityCode string, err error)
	StartType1Worker(ctx context.Context, event chan<- Type1Event) error
}

type Type2Provider interface {
	Provider

	StartType2Verification(ctx context.Context, identity string) (securityCode string, iden *Identity, err error)
}

type OAuth2Provider interface {
	Provider

	GetOAuth2URL(code string) string
	HandleOAuth2Callback(ctx context.Context, code string) (token *oauth2.Token, err error)
	GetOAuth2Identity(ctx context.Context, accessToken string) (identity *Identity, err error)
}
