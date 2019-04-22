package verifier_totp

import (
	"context"
	"github.com/pquerna/otp/totp"
	"github.com/themakers/identity/identity"
)

var _ identity.Verifier = new(Verifier)

//var _ identity.RegularVerification = new(Verifier)

type Verifier struct {
}

func (vf *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{Name: "TOTP", IdentityName: ""}
}

func New() *Verifier {
	ver := &Verifier{}
	return ver
}

func (ver *Verifier) StartStaticVerification(ctx context.Context, password_hash, password string) (err bool) {
	return totp.Validate(password_hash, password)
}
