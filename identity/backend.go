package identity

type Backend interface {
	CreateVerification(identity *Identity, securityCode string) (*Verification, error)
	GetVerification(verificationID string) (*Verification, error)

	GetUserByID(id string) (*User, error)
	GetUserByIdentity(prov, identity string) (*User, error)
	PutUserIdentity(id string, identity *Identity) (*User, error)
	CreateUser(identity *Identity) (*User, error)
}

type User struct {
	ID         string                         `bson:"_id" json:"ID"`
	Identities map[string]map[string]Identity `bson:"Identities" json:"Identities"` // /provider/identity/**
}

type IdentityFields map[string]string

type Identity struct {
	ID       string         `bson:"_id" json:"ID"`
	Provider string         `bson:"Provider" json:"Provider"`
	Fields   IdentityFields `bson:"Fields" json:"Fields"`
}

// TODO introduce security code input error count
type Verification struct {
	VerificationID string   `bson:"_id" json:"VerificationID"`
	SecurityCode   string   `bson:"SecurityCode" json:"SecurityCode"`
	Identity       Identity `bson:"Identity" json:"Identity"`
}
