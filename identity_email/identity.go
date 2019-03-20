package identity_email

import (
	"github.com/themakers/identity/identity"
	"strings"
)

var _ identity.Identity = new(Identity)

type Identity struct {
}

func (idn *Identity) Info() identity.IdentityData {

	return identity.IdentityData{Name: "Email"}
}

func (idn *Identity) NormalizeData(identity string) (result string) {
	//TODO maybe need a check character @ in email
	result = strings.ToLower(identity)
	return
}
