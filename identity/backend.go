package identity

type Backend interface {
	//-------------------Create section-----------------------------------------
	GetAuthentication(id string) (*Authentication, error)
	CreateAuthentication(id string, objective AuthenticationObjective, userID string) (*Authentication, error)
	SaveAuthentication(auth *Authentication) error

	//------------------Get section---------------------------------------------
	//CreateUser(identity *IdentityData, data *VerifierData) (*User, error)
	GetUser(id string) (*User, error)
	CreateUser(user *User) error
	SaveUser(user *User) error
	//GetUserByLogin(login, vername string) (*User, error)
	GetUserByIdentity(identityName, identity string) (*User, error)

	//------------------Add section ------------------------------------------------
	//AddUserIdentity(uid string, identity *IdentityData) (*User, error)
	//AddUserAuthenticationData(uid string, data *VerifierData) (*User, error)
	//AddUserToAuthentication(aid, uid string) (*Authentication, error)
	//AddTempAuthDataToAuth(aid string, data map[string]map[string]string) (*Authentication, error)
	//AddUserVerifier(uid string, data *VerifierData) (*User, error)
	//UpdateFactorStatus(aid, VerifierName string) error
	//DropIdentity(identity *IdentityData) error
}

type User struct {
	ID string `bson:"_id" json:"ID"`

	// TODO
	LastVerificationTime int64 `bson:"LastVerificationTime" json:"LastVerificationTime"`

	Identities        []IdentityData `bson:"Identities" json:"Identities"` // /name/identity/**
	Verifiers         []VerifierData `bson:"Verifiers" json:"Verifiers"`
	AuthFactorsNumber int            `bson:"AuthFactorsNumber" json:"AuthFactorsNumber"`

	Version int `bson:"Version" json:"Version"`
}

func (u *User) add(verd *VerifierData, idnd *IdentityData) {

}

type IdentityData struct {
	Name     string `bson:"Name" json:"Name"`
	Identity string `bson:"Identity" json:"Identity"`
}

//--------------------------------------------------------------------------------------------------------
type VerifierData struct {
	VerifierName       string `bson:"VerifierName" json:"VerifierName"`
	Identity           string `bson:"Identity" json:"Identity"`
	AuthenticationData B      `bson:"AuthenticationData" json:"AuthenticationData"` // /identity/value
	AdditionalData     B      `bson:"AdditionalData" json:"AdditionalData"`
}

func (u *User) findVerifierData(verifierName, identity string) *VerifierData {
	for _, vd := range u.Verifiers {
		if vd.VerifierName == verifierName {
			if identity != "" {
				if vd.Identity == identity {
					return &vd
				}
			} else {
				return &vd
			}
		}
	}
	return nil
}
