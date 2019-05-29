package identity_phone

import (
	"errors"
	"github.com/themakers/identity/identity"
	"strings"
	"unicode"
)

var _ identity.Identity = new(Identity)

type Identity struct {
}

func New() *Identity {
	return &Identity{}
}

func (idn *Identity) Info() identity.IdentityInfo {

	return identity.IdentityInfo{
		Name: "username",
	}
}

func (idn *Identity) NormalizeAndValidateData(identity string) (string, error) {
	for _, c := range identity {
		if !unicode.IsDigit(c) || !unicode.IsLetter(c) {
			return "", errors.New("invalid characters in username")
		}
	}
	return strings.ToLower(identity), nil

}
