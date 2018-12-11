package backend_mongo

import (
	"fmt"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/rs/xid"
	"github.com/themakers/identity/identity"
	"sync"
)

var _ identity.Backend = new(Backend)

const (
	collVerifications = "verifications"
	collUsers         = "users"
)

type Backend struct {
	mgo struct {
		db         string
		collPrefix string
		addr       string
		port       int
		sess       *mgo.Session
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

func (b *Backend) session(coll string) (*mgo.Collection, func(), error) {
	b.mgo.lock.Lock()
	defer b.mgo.lock.Unlock()

	if b.mgo.sess == nil {
		if sess, err := mgo.Dial(fmt.Sprintf("%s:%d", b.mgo.addr, b.mgo.port)); err != nil {
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

func (b *Backend) CreateVerification(iden *identity.Identity, securityCode string) (*identity.Verification, error) {
	coll, close, err := b.session(collVerifications)
	if err != nil {
		return nil, err
	}
	defer close()

	von := identity.Verification{
		VerificationID: xid.New().String(),
		SecurityCode:   securityCode,
		Identity:       *iden,
	}

	if err := coll.Insert(von); err != nil {
		return nil, err
	}

	return &von, nil
}

func (b *Backend) GetVerification(verificationID string) (*identity.Verification, error) {
	coll, close, err := b.session(collVerifications)
	if err != nil {
		return nil, err
	}
	defer close()

	von := identity.Verification{}

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

	if err := coll.Find(bson.M{"_id": id}).One(&user); err != nil && err == mgo.ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

func (b *Backend) GetUserByIdentity(prov, idn string) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()

	user := identity.User{}

	if err := coll.Find(bson.M{
		fmt.Sprintf("Identities.%s.%s", prov, idn): bson.M{"$exists": true},
	}).One(&user); err != nil && err == mgo.ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

func (b *Backend) PutUserIdentity(id string, iden *identity.Identity) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()

	user := identity.User{}
	//

	if _, err := coll.Find(bson.M{"_id": id}).Apply(mgo.Change{
		Update: bson.M{
			"$set": bson.M{
				fmt.Sprintf("Identities.%s.%s", iden.Provider, iden.ID): iden,
			},
		},
		ReturnNew: true,
	}, &user); err != nil && err == mgo.ErrNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

func (b *Backend) CreateUser(iden *identity.Identity) (*identity.User, error) {
	coll, close, err := b.session(collUsers)
	if err != nil {
		return nil, err
	}
	defer close()

	user := identity.User{
		ID: xid.New().String(),
		Identities: map[string]map[string]identity.Identity{
			iden.Provider: {
				iden.ID: *iden,
			},
		},
	}

	if err := coll.Insert(user); err != nil {
		return nil, err
	}

	return &user, nil
}
