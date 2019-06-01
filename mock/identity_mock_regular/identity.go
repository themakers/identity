package identity_mock_regular

import (
	"github.com/themakers/identity/identity"
	"strings"
)

var _ identity.Identity = new(Identity)

type Identity struct {
}

func New() *Identity {
	return &Identity{}
}

func (idn *Identity) Info() identity.IdentityInfo {
	return identity.IdentityInfo{
		Name: "mock_identity_regular",
	}
}

func (idn *Identity) NormalizeAndValidateIdentity(identity string) (result string, err error) {
	// TODO return error if identity contains non-alphabetic symbols
	identity = strings.ToLower(identity)
	return identity, nil
}
