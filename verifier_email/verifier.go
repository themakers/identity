package verifier_email

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_email"
)

type SenderFunc func(ctx context.Context, email, code string) error

var _ identity.Verifier = new(Verifier)
var _ identity.RegularVerifier = new(Verifier)

type Verifier struct {
	sfn SenderFunc
}

func New(sfn SenderFunc) *Verifier {
	return &Verifier{
		sfn: sfn,
	}
}

func (ver *Verifier) Info() identity.VerifierInfo {
	vi := identity.VerifierInfo{
		Name:         "code_by_email",
		IdentityName: new(identity_email.Identity).Info().Name,
	}

	return vi
}

func (ver *Verifier) StartRegularVerification(ctx context.Context, idn string, vd identity.VerifierData) (securityCode string, err error) {
	sc := fmt.Sprintf("%s-%s-%s", newSecurityCode(4), newSecurityCode(4), newSecurityCode(4))
	return sc, ver.sfn(ctx, idn, sc)
}

func newSecurityCode(l int) (code string) {
	b := [1]byte{}
	for i := 0; i < l; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		code += fmt.Sprint(int(b[0] % 10))
	}
	return
}
