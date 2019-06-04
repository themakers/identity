package backend_redis

import (
	"context"
	"github.com/themakers/identity/backend_test"
	"github.com/themakers/identity/identity"
	"testing"
)

func TestBackend(t *testing.T) {
	backend_test.Test(t, func(ctx context.Context) (identity.Backend, func(ctx context.Context) error, error) {
		back, err := New(Options{
			Address:   "localhost:27017",
			Namespace: "identity_test",
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
