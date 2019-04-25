package backend_mongo

import (
	"fmt"
	. "github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/rs/xid"
	"github.com/themakers/identity/identity"
	"log"
	"sync"
	"time"
)

var _ identity.Backend = new(Backend)

const (
	collVerifications   = "verifications"
	collUsers           = "users"
	collAuthentications = "authentications"
)

type Backend struct {
	mgo struct {
		db         string
		collPrefix string
		addr       string
		port       int
		sess       *Session
		lock       sync.Mutex
	}
}

func New(db, collPrefix, addr string, port int) (*Backend, error) {
	b := &Backend{}

	b.mgo.collPrefix = collPrefix
	b.mgo.db = db
	b.mgo.addr = addr
	b.mgo.port = port

	return b, nil
}

func (b *Backend) session(coll string) (*Collection, func(), error) {
	b.mgo.lock.Lock()
	defer b.mgo.lock.Unlock()

	if b.mgo.sess == nil {
		if sess, err := Dial(fmt.Sprintf("%s:%d", b.mgo.addr, b.mgo.port)); err != nil {
			return nil, func() {}, err
		} else {
			b.mgo.sess = sess
		}
	}

	sess := b.mgo.sess.Clone()

	return sess.DB(b.mgo.db).C(fmt.Sprintf("%s%s", b.mgo.collPrefix, coll)), func() {
		sess.Close()
	}, nil
}

func (b *Backend) CreateVerification(iden *identity.IdentityData, securityCode string) (*identity.Authentication, error) {
	coll, close, err := b.session(collVerifications)
	if err != nil {
		return nil, err
	}
	defer close()

	if err := coll.EnsureIndex(Index{
		Name:        "VerificationTTL",
		Key:         []string{"CreatedTime"},
		Unique:      false,
		Background:  true,
		ExpireAfter: 5 * time.Minute,
	}); err != nil {
		return nil, err
	}

	von := identity.Authentication{}

	if err := coll.Insert(von); err != nil {
		return nil, err
	}

	return &von, nil
}

func (b *Backend) GetVerification(verificationID string) (*identity.Authentication, error) {
	coll, close, err := b.session(collVerifications)
	if err != nil {
		return nil, err
	}
	defer close()

	von := identity.Authentication{}

	if err := coll.Find(bson.M{"_id": verificationID}).One(&von); err != nil {
		return nil, err
	}

	return &von, nil
}

func (b *Backend) GetUserByID(id string) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()

	user := identity.User{}

	if err := coll.Find(bson.M{"_id": id}).One(&user); err != nil && err == ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

func (b *Backend) GetUserByLogin(login, vername string) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()

	user := identity.User{}
	/*if err := coll.Find(bson.M{"Verifiers": bson.M{"$elemMatch": bson.M{"VerifierName": vername, "AuthenticationData": bson.M{login: bson.M{"$exists": true}}}}}).One(&user); err != nil && err == ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}*/
	if err := coll.Find(bson.M{fmt.Sprintf("Verifiers.AuthenticationData.%s", login): bson.M{"$exists": true}}).One(&user); err != nil {
		log.Println(err)
		return nil, err
	} else {
		return &user, nil
	}

	return &user, nil
}

func (b *Backend) GetUserByIdentity(idn string) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()
	user := identity.User{}
	if err := coll.Find(bson.M{"Identities": bson.M{"$elemMatch": bson.M{"Identity": idn}}}).One(&user); err != nil && user.ID == "" {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &user, nil
}

func (b *Backend) AddUserIdentity(id string, iden *identity.IdentityData) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()
	user := identity.User{}
	if _, err := coll.Find(bson.M{"_id": id}).Apply(Change{
		Update: bson.M{
			"$addToSet": bson.M{"Identities": iden},
		},
		ReturnNew: true,
	}, &user); err != nil && err == ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &user, nil
}

func (b *Backend) CreateUser(iden *identity.IdentityData, data *identity.VerifierData) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()

	user := identity.User{
		ID:                xid.New().String(),
		Identities:        []identity.IdentityData{identity.IdentityData{iden.Name, iden.Identity}},
		Verifiers:         []identity.VerifierData{identity.VerifierData{VerifierName: data.VerifierName, AdditionalData: data.AdditionalData, AuthenticationData: data.AuthenticationData}},
		AuthFactorsNumber: 2,
	}

	if err := coll.Insert(user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (b *Backend) CreateAuthentication(SessionToken, VerifierName string) (*identity.Authentication, error) {
	coll, close, err := b.session(collAuthentications)
	if err != nil {
		panic(err)
	}
	defer close()
	if err := coll.EnsureIndex(Index{
		Name:        "AuthenticationTTL",
		Key:         []string{"CreatedTime"},
		Unique:      false,
		Background:  true,
		ExpireAfter: 1 * time.Minute,
	}); err != nil {
		return nil, err
	}
	auth := identity.Authentication{}
	if err := coll.Find(bson.M{"_id": SessionToken}).One(&auth); err == nil {
		return &auth, identity.ErrAuthenticationForSessionAlreadyExist
	} else {
		fs := map[string]bool{VerifierName: false}
		auth = identity.Authentication{
			SessionToken:  SessionToken,
			FactorsCount:  99,
			FactorsStatus: fs,
			UserID:        "",
		}
		if err := coll.Insert(auth); err != nil {
			return nil, err
		}
	}
	return &auth, nil
}

func (b *Backend) GetAuthenticationBySessionToken(SessionToken string) (*identity.Authentication, error) {
	fs := make(map[string]bool)
	coll, close, err := b.session(collAuthentications)
	if err != nil {
		panic(err)
	}
	defer close()
	auth := identity.Authentication{}
	if err := coll.Find(bson.M{"_id": SessionToken}).One(&auth); err != nil {
		return &identity.Authentication{}, err
	} else {
		return &auth, nil
	}
	return &identity.Authentication{SessionToken: SessionToken, FactorsCount: 1, UserID: "123", FactorsStatus: fs}, nil
}

func (b *Backend) AddUserAuthenticationData(uid string, data *identity.VerifierData) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()
	user := identity.User{}
	if _, err := coll.Find(bson.M{"_id": uid}).Apply(Change{
		Update: bson.M{
			"$set": bson.M{
				"Verifiers.AuthenticationData": data.AuthenticationData,
				"Verifiers.AdditionalData":     data.AdditionalData,
			},
		}, ReturnNew: true,
	}, &user); err != nil {
		return nil, nil
	}

	return &user, nil
}

func (b *Backend) AddUserVerifier(uid string, data *identity.VerifierData) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()
	user := identity.User{}
	if _, err := coll.Find(bson.M{"_id": uid}).Apply(Change{
		Update: bson.M{
			"$addToSet": bson.M{"Verifiers": data},
		}, ReturnNew: true,
	}, &user); err != nil {
		return nil, nil
	}

	return &user, nil
}

func (b *Backend) AddUserToAuthentication(aid, uid string) (*identity.Authentication, error) {
	coll, close, err := b.session(collAuthentications)
	if err != nil {
		return nil, err
	}
	defer close()

	auth, err := b.GetAuthenticationBySessionToken(aid)
	if auth.UserID == "" {
		user, err := b.GetUserByID(uid)
		if err != nil {
			panic(err)
		}
		res := map[string]bool{}
		for _, ver := range user.Verifiers {
			res[ver.VerifierName] = false
		}

		if _, err := coll.Find(bson.M{"_id": aid}).Apply(Change{
			Update: bson.M{
				"$set": bson.M{
					"UserID":        uid,
					"FactorsCount":  user.AuthFactorsNumber,
					"FactorsStatus": res,
				},
			}, ReturnNew: true,
		}, &auth); err != nil {
			return nil, nil
		}
	}

	return auth, nil
}

func (b *Backend) AddTempAuthDataToAuth(aid string, data map[string]map[string]string) (*identity.Authentication, error) {
	coll, close, err := b.session(collAuthentications)
	if err != nil {
		return nil, err
	}
	defer close()

	auth := identity.Authentication{}

	if _, err := coll.Find(bson.M{"_id": aid}).Apply(Change{
		Update: bson.M{
			"$set": bson.M{
				"TempAuthenticationData": data,
			},
		}, ReturnNew: true,
	}, &auth); err != nil {
		return nil, nil
	}
	return &auth, nil

}

func (b *Backend) UpdateFactorStatus(aid, VerifierName string) error {
	coll, close, err := b.session(collAuthentications)
	defer close()
	if err != nil {
		return err
	}
	auth, err := b.GetAuthenticationBySessionToken(aid)
	res := auth.FactorsStatus
	res[VerifierName] = true
	if _, err := coll.Find(bson.M{"_id": aid}).Apply(Change{
		Update: bson.M{
			"$set": bson.M{
				"FactorsStatus": res,
			},
		}, ReturnNew: true,
	}, &auth); err != nil {
		panic(err)
	}
	return nil
}

func (b *Backend) GetUserByAuthenticationData(authkey, verifiername string) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	defer close()
	if err != nil {
		panic(err)
	}
	user := identity.User{}
	if err := coll.Find(bson.M{"Verifiers.VerifierName": verifiername}).One(&user); err != nil {
		return nil, err
	} else {
		return &user, err
	}
}
