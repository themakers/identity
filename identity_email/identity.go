package identity_email

import (
	"github.com/themakers/identity/identity"
	"strings"
)

var _ identity.Identity = new(Identity)

type Identity struct {
}

func New() *Identity {
	idn := &Identity{}
	return idn
}

func (idn *Identity) Info() identity.IdentityData {

	return identity.IdentityData{Name: "email"}
}

func (idn *Identity) NormalizeAndValidateData(identity string) (result string, err error) {
	//TODO maybe need a check character @ in email
	return strings.ToLower(identity), nil
}
