package verifier_password

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/themakers/identity/identity"
	"golang.org/x/crypto/scrypt"
)

var _ identity.Verifier = new(Verifier)
var _ identity.StaticVerifier = new(Verifier)

type Verifier struct {
}

func (v *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{
		Name:         "password",
		IdentityName: "",
	}
}

func New() *Verifier {
	return &Verifier{}
}

func (v *Verifier) hash(passwd string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(passwd), salt, 1<<15, 8, 1, 32)
}

func (v *Verifier) InitStaticVerifier(ctx context.Context, verifierData *identity.VerifierData, args identity.M) (res identity.M, err error) {
	// FIXME: Validate password
	password := args["password"]

	salt := newRandomSlice(32)
	hash, err := v.hash(password, salt)
	if err != nil {
		return nil, err
	}

	verifierData.AuthenticationData = map[string][]byte{
		"hash": hash,
		"salt": salt,
	}

	return identity.M{}, nil
}

func (v *Verifier) StartStaticVerification(ctx context.Context, verifierData identity.VerifierData, inputCode string) (bool, error) {
	hash := verifierData.AuthenticationData["hash"]
	salt := verifierData.AuthenticationData["salt"]

	inputHash, err := v.hash(inputCode, []byte(salt))
	if err != nil {
		return false, err
	}

	if string(inputHash) == string(hash) {
		return true, nil
	} else {
		return false, nil
	}
}

func newRandomSlice(l int) (b []byte) {
	b = make([]byte, l)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
