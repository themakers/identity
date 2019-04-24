package verifier_password

import (
	"context"
	"github.com/themakers/identity/identity"
	"golang.org/x/crypto/scrypt"
)

const salt = "salt"

var _ identity.Verifier = new(Verifier)

//var _ identity.RegularVerification = new(Verifier)

type Verifier struct {
}

func (vf *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{Name: "Login", IdentityName: ""}
}

func New() *Verifier {
	ver := &Verifier{}
	return ver
}

func (ver *Verifier) StartStaticVerification(ctx context.Context, password_hash, password, login string) (err bool) {
	hash, hash_err := scrypt.Key([]byte(password), []byte(salt), 1<<15, 8, 1, 32)
	if hash_err != nil {
		panic(hash_err)
	}
	return string(hash) == password_hash
}
