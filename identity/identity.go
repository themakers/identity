package identity

type IdentityInfo struct {
	Name string
}

type Identity interface {
	Info() IdentityInfo
	NormalizeAndValidateData(identity string) (Identity string, err error)
}
