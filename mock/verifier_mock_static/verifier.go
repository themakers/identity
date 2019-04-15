package verifier_mock_static

import (
	"context"
	"github.com/themakers/identity/identity"
)

var _ identity.Verifier = new(Verifier)

type Verifier struct {
	cb Callback
}

type Callback func(login, pass string)

func New(cb Callback) *Verifier {
	return &Verifier{cb: cb}
}

func (ver *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{Name: "mock_static", IdentityName: ""}

}

func (ver *Verifier) StartStaticVerification(ctx context.Context) bool {
	return true
}
