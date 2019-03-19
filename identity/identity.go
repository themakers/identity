package identity

type Identity interface {
	Info() IdentityData

	NormalizeData (identity string) (string)
}
