package verifier_mock_oauth2

import (
	"context"
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
)

var _ identity.Verifier = new(Verifier)

type Verifier struct {
	cb Callback
}

func (ver *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		IdentityName: "mock_identity",
		Name:         "mock_oauth2",
	}

}

type Callback func(idn string)

func New(cb Callback) *Verifier {
	return &Verifier{cb: cb}
}

func (ver *Verifier) GetOAuth2URL(code string) string {
	return "http://oauth2provider.com"
}

func (ver *Verifier) HandleOAuth2Callback(ctx context.Context, code string) (token *oauth2.Token, err error) {
	return &oauth2.Token{AccessToken: "mock_access_token"}, nil
}

func (ver *Verifier) GetOAuth2Identity(ctx context.Context, accessToken string) (idn *identity.IdentityData, vd *identity.VerifierData, err error) {
	idn = &identity.IdentityData{Identity: "uid1234432", Name: ver.Info().IdentityName}
	vd = &identity.VerifierData{VerifierName: ver.Info().Name, AuthenticationData: map[string]string{}, AdditionalData: map[string]string{"phonenum": "79991112233"}}
	return idn, vd, nil
}
