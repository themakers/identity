package verifier_sms

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_phone"
)

type SenderFunc func(ctx context.Context, phone, code string, flash bool) error

var _ identity.Verifier = new(Verifier)
var _ identity.RegularVerifier = new(Verifier)

type Verifier struct {
	codeLen int
	flash   bool
	sfn     SenderFunc
}

func New(codeLen int, flash bool, sfn SenderFunc) *Verifier {
	if codeLen <= 0 {
		codeLen = 6
	}
	return &Verifier{
		codeLen: codeLen,
		flash:   flash,
		sfn:     sfn,
	}
}

func (ver *Verifier) Info() identity.VerifierInfo {
	vi := identity.VerifierInfo{
		Name:         "code_by_sms",
		IdentityName: new(identity_phone.Identity).Info().Name,
	}

	if ver.flash {
		vi.Name = "code_by_flashsms"
	}

	return vi
}

func (ver *Verifier) StartRegularVerification(ctx context.Context, idn string, vd identity.VerifierData) (securityCode string, err error) {
	sc := newSecurityCode(ver.codeLen)
	return sc, ver.sfn(ctx, idn, sc, ver.flash)
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
