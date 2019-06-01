package verifier_mock_oauth2

import (
	"context"
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
)

var _ identity.OAuth2Verifier = new(Verifier)

type Verifier struct {
	idn  string
	ivfn IdentityVerifiedFn
}

func (ver *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name: "mock_oauth2",
	}
}

type IdentityVerifiedFn func(idn string)

func New(idn string, ivfn IdentityVerifiedFn) *Verifier {
	return &Verifier{
		idn:  idn,
		ivfn: ivfn,
	}
}

func (ver *Verifier) GetOAuth2URL(code string) string {
	return "http://oauth2provider.com"
}

func (ver *Verifier) HandleOAuth2Callback(ctx context.Context, code string) (token *oauth2.Token, err error) {
	return &oauth2.Token{AccessToken: "mock_access_token"}, nil
}

func (ver *Verifier) GetOAuth2Identity(ctx context.Context, accessToken string) (idn *identity.IdentityData, vd *identity.VerifierData, err error) {
	return &identity.IdentityData{
			Identity: ver.idn,
			Name:     ver.Info().IdentityName,
		}, &identity.VerifierData{
			Name:               ver.Info().Name,
			Identity:           ver.idn,
			AuthenticationData: nil,
			AdditionalData:     identity.B{},
		}, nil
}
