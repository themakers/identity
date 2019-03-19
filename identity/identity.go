package identity

type Identity interface {
	Info() IdentityInfo

	NormalizeData (identity Identity) (Identity)
}
