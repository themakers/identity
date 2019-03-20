package identity_phone

import (
	"github.com/themakers/identity/identity"
	"unicode"
)

var _ identity.Identity = new(Identity)

type Identity struct {
}

func (idn *Identity) Info() identity.IdentityData {

	return identity.IdentityData{Name: "Phone"}
}

func (idn *Identity) NormalizeData(identity string) (result string) {
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
	return

}
