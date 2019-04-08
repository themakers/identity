package identity

type Backend interface {
	CreateVerification(iden *IdentityData, securityCode string) (*Authentication, error)
	GetAuthenticationBySessionToken(SessionToken string) (*Authentication, error)
	CreateAuthentication(SessionToken string) (*Authentication, error)
	GetVerification(verificationID string) (*Authentication, error)
	GetUserByID(id string) (*User, error)
	GetUserByIdentity(identity string) (*User, error)
	AddUserIdentity(uid string, identity *IdentityData) (*User, error)
	CreateUser(identity *IdentityData) (*User, error)
	//DropIdentity(identity *IdentityData) error
}

// TODO add a multifactor criterea
type User struct {
	ID string `bson:"_id" json:"ID"`
	//	SessionID  []string         `bson:"session_id" json:"Session_id"`
	Identities        []IdentityData `bson:"Identities" json:"Identities"` // /name/identity/**
	Verifiers         []VerifierData `bson:"Verifiers" json:"Verifiers"`
	AuthFactorsNumber int            `bson:"AuthFactorsNumber" json:"AuthFactorsNumber"`
}

type IdentityData struct {
	Name     string `bson:"Name" json:"Name"`
	Identity string `bson:"Identity" json:"Identity"`
}

//--------------------------------------------------------------------------------------------------------
type VerifierData struct {
	AuthenticationData map[string]string `bson:"AuthenticationData" json:"AuthenticationData"` // /identity/value
	AdditionalData     map[string]string `bson:"AdditionalData" json:"AdditionalData"`
}

type Authentication struct {
	SessionToken  string          `bson:"_id" json:"SessionToken"`
	UserID        string          `bson:"UserID" json:"UserID"`
	FactorsCount  int             `bson:"FactorsCount" json:"FactorsCount"`
	FactorsStatus map[string]bool `bson:"FactorsStatus" json:"FactorsStatus"` // /name/status
}
