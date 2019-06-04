package identity_phone

import (
	"errors"
	"github.com/themakers/identity/identity"
	"unicode"
)

var ErrPhoneNumberNotValid = errors.New("phone number isn't valid")

var _ identity.Identity = new(Identity)

type Identity struct {
}

func New() *Identity {
	return &Identity{}
}

func (idn *Identity) Info() identity.IdentityInfo {
	return identity.IdentityInfo{
		Name: "phone",
	}
}

func (idn *Identity) NormalizeAndValidateIdentity(identity string) (result string, err error) {
	for _, c := range identity {
		if unicode.IsDigit(c) {
			result += string(rune(c))
		}
	}
	if len(result) == 11 && result[0] == '8' {
		result = string(rune('7')) + result[1:]
	} else if len(result) == 10 && result[0] == '9' {
		result = string(rune('7')) + result[:]
	}
	return result, nil

}
