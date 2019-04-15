package verifier_password

import (
	"context"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/themakers/identity/identity"
	"golang.org/x/crypto/bcrypt"
)

const mgo_url = ""
const mgo_bd_name = ""
const mgo_collection_name = ""

var _ identity.Verifier = new(Verifier)

//var _ identity.RegularVerification = new(Verifier)

type Verifier struct {
}

func (vf *Verifier) Info() identity.VerifierInfo {
	return identity.VerifierInfo{Name: "Login", IdentityName: "password"}
}

func New() *Verifier {
	ver := &Verifier{}
	return ver
}

func (ver *Verifier) StartStaticVerification(ctx context.Context, login string, password string) (iden *identity.VerifierData, err error) {

	session, err := mgo.Dial(mgo_url)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	c := session.DB(mgo_bd_name).C(mgo_collection_name)
	var user UserInfo
	err = c.Find(bson.M{
		"login": login,
	}).One(&user)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PwdHash), []byte(password))
	if err != nil {
		return nil, err
	} else {
		AD := make(map[string]string)
		AD[login] = password
		return &identity.VerifierData{
			VerifierName:       "Login",
			AuthenticationData: AD,
		}, nil
	}
}

type UserInfo struct {
	Id      bson.ObjectId `bson:"_id"`
	Login   string        `bson:"login"`
	PwdHash string        `bson:"pwd"`
}
