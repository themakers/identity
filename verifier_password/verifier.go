package verifier_password

import (
	"context"
	"github.com/themakers/identity/identity"
	"golang.org/x/crypto/bcrypt"
)

var _ identity.Verifier = new(Verifier)

//var _ identity.RegularVerification = new(Verifier)

type Verifier struct {
}

func (vf *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{Name: "Login", IdentityName: "password"}
}

func New() *Verifier {
	ver := &Verifier{}
	return ver
}

func (ver *Verifier) StartStaticVerification(ctx context.Context, password_hash, password, login string) (err error) {
	return bcrypt.CompareHashAndPassword([]byte(password_hash), []byte(password))
}
