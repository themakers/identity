package identity

type IdentityInfo struct {
	Name string
}

type Identity interface {
	Info() IdentityInfo
	NormalizeAndValidateIdentity(idn string) (idnNormalized string, err error)
}
