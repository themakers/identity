package identity

import (
	"context"
	"golang.org/x/oauth2"
)

//-----------------------------------------------------------------------------------------
//-------------------------------Provider interfaces and structs---------------------------
//-----------------------------------------------------------------------------------------

type ProviderInfo struct {
	Name string
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

//-------------------------------------------------------------------------------------------
//------------------------Verifications interfaces and structs-------------------------------
//-------------------------------------------------------------------------------------------

type Type1Event struct {
	Identity     *Identity
	SecurityCode string
}

type Type1Provider interface {
	Provider

	// identity - optional
	//authentification process start
	StartType1Verification(ctx context.Context) (target, securityCode string, err error)
	StartType1Worker(ctx context.Context, event chan<- Type1Event) error
	//authentification process finish
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
