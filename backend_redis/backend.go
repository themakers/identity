package backend_redis

import (
	"context"
	"github.com/themakers/identity/identity"
)

type Options struct {
	Address   string
	Namespace string
}

var _ identity.Backend = new(Backend)

type Backend struct {
	ops Options
}

func New(ops Options) (*Backend, error) {
	b := &Backend{
		ops: ops,
	}

	return b, nil
}

func (b *Backend) Cleanup(ctx context.Context) error {
	panic("implement me")
}

func (b *Backend) GetAuthentication(ctx context.Context, id string) (*identity.Authentication, error) {
	panic("implement me")
}

func (b *Backend) CreateAuthentication(ctx context.Context, id string, objective identity.AuthenticationObjective, userID string) (*identity.Authentication, error) {
	panic("implement me")
}

func (b *Backend) SaveAuthentication(ctx context.Context, auth *identity.Authentication) (*identity.Authentication, error) {
	panic("implement me")
}

func (b *Backend) RemoveAuthentication(ctx context.Context, id string) error {
	panic("implement me")
}

func (b *Backend) GetUser(ctx context.Context, id string) (*identity.User, error) {
	panic("implement me")
}

func (b *Backend) CreateUser(ctx context.Context, user *identity.User) (*identity.User, error) {
	panic("implement me")
}

func (b *Backend) SaveUser(ctx context.Context, user *identity.User) (*identity.User, error) {
	panic("implement me")
}

func (b *Backend) GetUserByIdentity(ctx context.Context, identityName, identity string) (*identity.User, error) {
	panic("implement me")
}
