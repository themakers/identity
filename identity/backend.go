package identity

import "time"

type Backend interface {
	CreateVerification(identity *IdentityData, securityCode string) (*Verification, error)
	GetVerification(verificationID string) (*Verification, error)
	GetUserByID(id string) (*User, error)
	GetUserByIdentity(identity string) (*User, error)
	AddUserIdentity(uid string, identity *IdentityData) (*User, error)
	CreateUser(identity *IdentityData) (*User, error)
}

type User struct {
	ID         string         `bson:"_id" json:"ID"`
	Identities []IdentityData `bson:"Identities" json:"Identities"` // /name/identity/**
	Staticdata []VerifierData `bson:"StaticData" json:"Staticdata"`
}

type IdentityData struct {
	Name     string `bson:"Name" json:"Name"`
	Identity string `bson:"Identity" json:"Identity"`
}

//--------------------------------------------------------------------------------------------------------
type VerifierData struct {
	AuthenticationData map[string]string `bson:"AuthenticationData" json:"AuthenticationData"` // /name/value
	AdditionalData     map[string]string `bson:"AdditionalData" json:"AdditionalData"`
}

//--------------------------------------------------------------------------------------------------------
// TODO introduce security code input error count
type Verification struct {
	VerificationID string       `bson:"_id" json:"VerificationID"`
	SecurityCode   string       `bson:"SecurityCode" json:"SecurityCode"`
	Identity       IdentityData `bson:"Identity" json:"Identity"`
	CreatedTime    time.Time    `bson:"CreatedTime" json:"CreatedTime"`
}
