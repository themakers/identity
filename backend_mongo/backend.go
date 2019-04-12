package backend_mongo

import (
	"fmt"
	. "github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/rs/xid"
	"github.com/themakers/identity/identity"
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
	//

	if _, err := coll.Find(bson.M{"_id": id}).Apply(Change{
		Update: bson.M{
			"$set": bson.M{
				fmt.Sprintf("Identities.%s.%s", iden.Name, iden.Identity): iden,
			},
		},
		ReturnNew: true,
	}, &user); err != nil && err == ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

func (b *Backend) CreateUser(iden *identity.IdentityData) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()

	user := identity.User{
		ID:         xid.New().String(),
		Identities: []identity.IdentityData{identity.IdentityData{iden.Name, iden.Identity}},
	}

	if err := coll.Insert(user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (b *Backend) CreateAuthentication(SessionToken string) (*identity.Authentication, error) {
	coll, close, err := b.session(collAuthentications)
	if err != nil {
		panic(err)
	}
	defer close()
	auth := identity.Authentication{}
	if err := coll.Find(bson.M{"_id": SessionToken}).One(&auth); err == nil {
		return &auth, identity.ErrAuthenticationForSessionAlreadyExist
	} else {
		fs := make(map[string]bool)
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

// todo realise a multiple add to Authentication

func (b *Backend) UpdateAuthentication(token string, updatedata map[string]string) (bool, error) {
	return false, nil
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
			"$push": bson.M{"Verifiers": data},
		}, ReturnNew: true,
	}, &user); err != nil {
		return nil, nil
	}
	/*

		if _, err := coll.Find(bson.M{"_id": uid}).Apply()


		if _, err := coll.Find(bson.M{"_id": id}).Apply(mgo.Change{
			Update: bson.M{
				"$set": bson.M{
					fmt.Sprintf("Identities.%s.%s", iden.Name, iden.Identity): iden,
				},
			},
			ReturnNew: true,
		}, &user); err != nil && err == mgo.ErrNotFound {
			return nil, nil
		} else if err != nil {
			return nil, err
		}*/

	return &user, nil

}

func (b *Backend) AddUserToAuthentication(aid, uid string) (*identity.Authentication, error) {
	coll, close, err := b.session(collAuthentications)
	if err != nil {
		return nil, err
	}
	defer close()

	auth := identity.Authentication{}

	if _, err := coll.Find(bson.M{"_id": aid}).Apply(Change{
		Update: bson.M{
			"$set": bson.M{
				"UserID": uid,
			},
		}, ReturnNew: true,
	}, &auth); err != nil {
		return nil, nil
	}
	return &auth, nil
}
