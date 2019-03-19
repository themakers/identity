package identity_phone

import "github.com/themakers/identity/identity"

var _ identity.Identity = new(Identity)

type Identity struct {

}

func (idn *Identity) Info() identity.IdentityData {

	return identity.IdentityData{}
}

func (idn *Identity) NormalizeData(identity string)  string{

	return identity

}