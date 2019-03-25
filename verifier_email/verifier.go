package verifier_email

import (
	"context"
	"github.com/themakers/identity/identity"
)

var _ identity.Verifier = new(Verifier)

//var _ identity.RegularVerification = new(Verifier)

type Verifier struct {
}

func (vf *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{Name: "EmailCodeCheck", IdentityName: "email"}
}

func New() *Verifier {
	ver := &Verifier{}
	return ver
}

func (ver *Verifier) StartRegularVerification(ctx context.Context, identity string) (secuiritycode string) {
	return
}

func (vf *Verifier) RegularVerification(ctx context.Context) {
	return
}
