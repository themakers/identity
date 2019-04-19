package identity

type Backend interface {
	//-------------------Create section-----------------------------------------
	CreateVerification(iden *IdentityData, securityCode string) (*Authentication, error)
	CreateAuthentication(SessionToken, VerifierName string) (*Authentication, error)
	CreateUser(identity *IdentityData, data *VerifierData) (*User, error)
	//------------------Get section---------------------------------------------
	GetAuthenticationBySessionToken(SessionToken string) (*Authentication, error)
	GetVerification(verificationID string) (*Authentication, error)
	GetUserByID(id string) (*User, error)
	GetUserByIdentity(identity string) (*User, error)
	//------------------Add section ------------------------------------------------
	AddUserIdentity(uid string, identity *IdentityData) (*User, error)
	AddUserAuthenticationData(uid string, data *VerifierData) (*User, error)
	AddUserToAuthentication(aid, uid string) (*Authentication, error)
	AddTempAuthDataToAuth(aid string, data map[string]map[string]string) (*Authentication, error)
	UpdateFactorStatus(aid, VerifierName string) error
	//DropIdentity(identity *IdentityData) error
}

type User struct {
	ID                string         `bson:"_id" json:"ID"`
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
	VerifierName       string            `bson:"VerifierName" json:"VerifierName"`
	AuthenticationData map[string]string `bson:"AuthenticationData" json:"AuthenticationData"` // /identity/value
	AdditionalData     map[string]string `bson:"AdditionalData" json:"AdditionalData"`
}

type Authentication struct {
	SessionToken           string                       `bson:"_id" json:"SessionToken"`
	UserID                 string                       `bson:"UserID" json:"UserID"`
	FactorsCount           int                          `bson:"FactorsCount" json:"FactorsCount"`
	TempAuthenticationData map[string]map[string]string `bson:"TempAuthenticationData" json:"TempAuthenticationData"` // /verifiername/identity/value
	FactorsStatus          map[string]bool              `bson:"FactorsStatus" json:"FactorsStatus"`                   // /name/status
}
