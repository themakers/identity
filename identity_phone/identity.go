package identity_phone

import (
	"github.com/themakers/identity/identity"
	"unicode"
)

var _ identity.Identity = new(Identity)

type Identity struct {
}

func (idn *Identity) Info() identity.IdentityData {

	return identity.IdentityData{Name: "phone"}
}

func (idn *Identity) NormalizeandValidateData(identity string) (result string, err error) {
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
