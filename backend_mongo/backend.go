package backend_mongo

import (
	"context"
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

func (b *Backend) Cleanup(ctx context.Context) error {
	if err := b.client.UseSession(ctx, func(sctx mongo.SessionContext) error {
		if _, err := sctx.WithTransaction(sctx, func(sctx mongo.SessionContext) (interface{}, error) {

			if err := b.coll(collAuthentications).Drop(sctx); err != nil {
				return nil, err
			}
			if err := b.coll(collUsers).Drop(sctx); err != nil {
				return nil, err
			}

			return nil, nil
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (b *Backend) GetAuthentication(ctx context.Context, id string) (*identity.Authentication, error) {
	var auth identity.Authentication
	if err := b.coll(collAuthentications).FindOne(ctx, bson.M{"_id": id}).Decode(&auth); err != nil {
		return nil, err
	}
	return &auth, nil
}

func (b *Backend) CreateAuthentication(ctx context.Context, id string, objective identity.AuthenticationObjective, userID string) (*identity.Authentication, error) {
	auth := identity.Authentication{
		ID:        id,
		Objective: objective,
		UserID:    userID,
	}
	if _, err := b.coll(collAuthentications).InsertOne(ctx, auth); err != nil {
		return nil, err
	}
	return &auth, nil
}

func (b *Backend) SaveAuthentication(ctx context.Context, auth *identity.Authentication) error {
	ver := auth.Version
	auth.Version++
	if _, err := b.coll(collAuthentications).UpdateOne(ctx, bson.M{
		"_id":     auth.ID,
		"Version": ver,
	}, auth); err != nil {
		return err
	}
	return nil
}

func (b *Backend) GetUser(ctx context.Context, id string) (*identity.User, error) {
	var user identity.User
	if err := b.coll(collUsers).FindOne(ctx, bson.M{"_id": id}).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (b *Backend) CreateUser(ctx context.Context, user *identity.User) error {
	if _, err := b.coll(collUsers).InsertOne(ctx, user); err != nil {
		return err
	}
	return nil
}

func (b *Backend) SaveUser(ctx context.Context, user *identity.User) error {
	ver := user.Version
	user.Version++
	if _, err := b.coll(collUsers).UpdateOne(ctx, bson.M{
		"_id":     user.ID,
		"Version": ver,
	}, user); err != nil {
		return err
	}
	return nil
}

func (b *Backend) GetUserByIdentity(ctx context.Context, idnName, idn string) (*identity.User, error) {
	var user identity.User
	if err := b.coll(collUsers).FindOne(ctx, bson.M{
		"Identities": bson.M{
			"Name":     idnName,
			"Identity": idn,
		},
	}).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}
