package identity

type IdentityInfo struct {
	Name string
}

type Identity interface {
	Info() IdentityInfo
	NormalizeAndValidateIdentity(idn string) (idnNormalized string, err error)
}

////////////////////////////////////////////////////////////////
////
////

var _ Identity = new(identityStub)

type identityStub struct {
	name string
}

func newIdentityStub(name string) *identityStub {
	return &identityStub{name: name}
}

func (idn *identityStub) Info() IdentityInfo {
	return IdentityInfo{Name: idn.name}
}

func (idn *identityStub) NormalizeAndValidateIdentity(identity string) (string, error) {
	return identity, nil
}
