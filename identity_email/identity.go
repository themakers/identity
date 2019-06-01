package identity_email

import (
	"errors"
	"github.com/themakers/identity/identity"
	"regexp"
	"strings"
)

var _ identity.Identity = new(Identity)
var ErrEmailNotValid = errors.New("Email is not valid")

type Identity struct {
}

func New() *Identity {
	idn := &Identity{}
	return idn
}

func (idn *Identity) Info() identity.IdentityInfo {
	return identity.IdentityInfo{Name: "email"}
}

func (idn *Identity) NormalizeAndValidateIdentity(identity string) (result string, err error) {
	mailRegExp := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if mailRegExp.MatchString(identity) {
		return strings.ToLower(identity), nil
	} else {
		return "", ErrEmailNotValid
	}
}
