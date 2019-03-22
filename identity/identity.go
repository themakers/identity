package identity

type Identity interface {
	Info() IdentityData
	NormalizeAndValidateData(identity string) (Identity string, err error)
}
