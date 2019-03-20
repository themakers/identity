package identity

type Identity interface {
	Info() IdentityData

	NormalizeandValidateData(identity string) (Identity string, err error)
}
