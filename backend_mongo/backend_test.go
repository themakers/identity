package backend_mongo

import (
	"context"
	"github.com/themakers/identity/backend_test"
	"github.com/themakers/identity/identity"
	"testing"
)

func Test_Backend(t *testing.T) {
	backend_test.Test(t, func(ctx context.Context) (identity.Backend, func(ctx context.Context) error, error) {
		back, err := New(Options{
			URI:              "mongodb://localhost:27017/?replicaSet=rs0",
			DBName:           "test_identity_backend",
			CollectionPrefix: "identity_",
		})

		if err != nil {
			return nil, func(context.Context) error {
				return nil
			}, err
		}

		cleanup := func(ctx context.Context) error {
			return back.Cleanup(ctx)
		}

		return back, cleanup, nil
	})
}
