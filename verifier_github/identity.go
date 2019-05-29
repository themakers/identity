package verifier_github

import (
	"github.com/themakers/identity/identity"
)

var _ identity.Identity = new(Identity)

type Identity struct {
}

func NewIdentity() *Identity {
	return &Identity{}
}

func (idn *Identity) Info() identity.IdentityInfo {
	return identity.IdentityInfo{
		Name: "github",
	}
}

func (idn *Identity) NormalizeAndValidateData(identity string) (string, error) {
	return identity, nil
}
