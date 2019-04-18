package verifier_mock_oauth2

import (
	"github.com/themakers/identity/identity"
	"golang.org/x/oauth2"
)

var _ identity.Verifier = new(Verifier)

type Verifier struct{}

func (ver *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		IdentityName: "mock_identity",
		Name:         "mock_oauth2",
	}

}

func (ver *Verifier) GetOAuth2URL() string {
	return "http://oauth2provider.com"
}

func (ver *Verifier) HandleOAuth2Callback() (token *oauth2.Token, err error) {

	return
}

func (ver *Verifier) GetOAuth2Identity() (identity *identity.IdentityData, err error) {
	return
}
