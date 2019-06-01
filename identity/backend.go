package identity

import "context"

type Backend interface {
	GetAuthentication(ctx context.Context, id string) (*Authentication, error)
	CreateAuthentication(ctx context.Context, id string, objective AuthenticationObjective, userID string) (*Authentication, error)
	SaveAuthentication(ctx context.Context, auth *Authentication) (*Authentication, error)
	RemoveAuthentication(ctx context.Context, id string) error

	GetUser(ctx context.Context, id string) (*User, error)
	CreateUser(ctx context.Context, user *User) (*User, error)
	SaveUser(ctx context.Context, user *User) (*User, error)
	GetUserByIdentity(ctx context.Context, identityName, identity string) (*User, error)
}
