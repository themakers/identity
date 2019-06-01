package verifier_mock_regular

import (
	"context"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/mock/identity_mock_regular"
	"math/rand"
	"strconv"
)

var _ identity.Verifier = new(Verifier)

type Verifier struct {
	cb Callback
}

type Callback func(idn, code string)

func New(cb Callback) *Verifier {
	return &Verifier{
		cb: cb,
	}
}

func (ver *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name:         "mock_regular",
		IdentityName: new(identity_mock_regular.Identity).Info().Name,
	}
}

func (ver *Verifier) StartRegularVerification(ctx context.Context, idn string, verifierData identity.VerifierData) (securityCode string, err error) {
	code := strconv.Itoa(1000 + rand.Intn(8999))
	ver.cb(idn, code)
	return code, nil
}
