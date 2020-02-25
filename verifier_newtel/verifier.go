package verifier_newtel

import (
	"context"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_phone"
)

type SenderFunc func(ctx context.Context, phone string) (string, error)

var _ identity.Verifier = new(Verifier)
var _ identity.RegularVerifier = new(Verifier)

type Verifier struct {
	sfn     SenderFunc
}

func New(sfn SenderFunc) *Verifier {
	return &Verifier{
		sfn:     sfn,
	}
}

func (ver *Verifier) Info() identity.VerifierInfo {
	vi := identity.VerifierInfo{
		Name:         "code_by_newtel",
		IdentityName: new(identity_phone.Identity).Info().Name,
	}

	return vi
}

func (ver *Verifier) StartRegularVerification(ctx context.Context, idn string, vd identity.VerifierData) (securityCode string, err error) {
	return ver.sfn(ctx, idn)
}
