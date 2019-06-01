package backend_mongo

import (
	"context"
	"errors"
	"fmt"
	"github.com/themakers/identity/identity"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	collUsers           = "users"
	collAuthentications = "authentications"
)

type Options struct {
	DBName           string
	CollectionPrefix string
	URI              string
}

var _ identity.Backend = new(Backend)

type Backend struct {
	ops Options

	client *mongo.Client
}

func New(ops Options) (*Backend, error) {
	b := &Backend{
		ops: ops,
	}

	client, err := mongo.NewClient(options.Client().ApplyURI(b.ops.URI))
	if err != nil {
		return nil, err
	} else {
		if err := client.Connect(context.TODO()); err != nil {
			return nil, err
		}
		b.client = client
	}

	return b, nil
}

func (b *Backend) db() *mongo.Database {
	return b.client.Database(b.ops.DBName)
}

func (b *Backend) coll(coll string) *mongo.Collection {
	return b.db().Collection(fmt.Sprintf("%s%s", b.ops.CollectionPrefix, coll))
}

func (b *Backend) txn(ctx context.Context, txfn func(ctx mongo.SessionContext) error) error {
	return b.client.UseSession(ctx, func(ctx mongo.SessionContext) error {
		if _, err := ctx.WithTransaction(ctx, func(ctx mongo.SessionContext) (interface{}, error) {
			return nil, txfn(ctx)
		}); err != nil {
			return err
		} else {
			return nil
		}
	})
}

func (b *Backend) Clear(ctx context.Context) error {
	return b.txn(ctx, func(ctx mongo.SessionContext) error {
		if _, err := b.coll(collAuthentications).DeleteMany(ctx, bson.M{}); err != nil {
			return err
		}
		if _, err := b.coll(collUsers).DeleteMany(ctx, bson.M{}); err != nil {
			return err
		}
		return nil
	})
}

func (b *Backend) GetAuthentication(ctx context.Context, id string) (*identity.Authentication, error) {
	var auth identity.Authentication
	if err := b.coll(collAuthentications).FindOne(ctx, bson.M{"_id": id}).Decode(&auth); err == mongo.ErrNoDocuments {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &auth, nil
}

func (b *Backend) CreateAuthentication(ctx context.Context, id string, objective identity.AuthenticationObjective, userID string) (*identity.Authentication, error) {
	auth := identity.Authentication{
		ID:        id,
		Objective: objective,
		UserID:    userID,
		Version:   1,
	}
	if _, err := b.coll(collAuthentications).InsertOne(ctx, auth); err != nil {
		return nil, err
	}
	return &auth, nil
}

func (b *Backend) SaveAuthentication(ctx context.Context, auth *identity.Authentication) (result *identity.Authentication, err error) {
	ver := auth.Version
	auth.Version++
	if err := b.coll(collAuthentications).FindOneAndUpdate(ctx, bson.M{
		"_id":     auth.ID,
		"Version": ver,
	}, bson.M{
		"$set": auth,
	}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (b *Backend) RemoveAuthentication(ctx context.Context, id string) error {
	if _, err := b.coll(collAuthentications).DeleteOne(ctx, bson.M{
		"_id": id,
	}); err != nil {
		return err
	}
	return nil
}

func (b *Backend) GetUser(ctx context.Context, id string) (*identity.User, error) {
	var user identity.User
	if err := b.coll(collUsers).FindOne(ctx, bson.M{"_id": id}).Decode(&user); err == mongo.ErrNoDocuments {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &user, nil
}

func (b *Backend) CreateUser(ctx context.Context, user *identity.User) (*identity.User, error) {
	user.Version = 1
	if _, err := b.coll(collUsers).InsertOne(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

func (b *Backend) SaveUser(ctx context.Context, user *identity.User) (result *identity.User, err error) {
	if user.ID == "" {
		return nil, errors.New("user id missing")
	}
	ver := user.Version
	user.Version++
	if err := b.coll(collUsers).FindOneAndUpdate(ctx, bson.M{
		"_id":     user.ID,
		"Version": ver,
	}, bson.M{
		"$set": user,
	}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (b *Backend) GetUserByIdentity(ctx context.Context, idnName, idn string) (*identity.User, error) {
	var user identity.User
	if err := b.coll(collUsers).FindOne(ctx, bson.M{
		"Identities": bson.M{
			"Name":     idnName,
			"Identity": idn,
		},
	}).Decode(&user); err == mongo.ErrNoDocuments {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &user, nil
}
