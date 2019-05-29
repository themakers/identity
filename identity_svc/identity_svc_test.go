package identity_svc

import (
	"context"
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/themakers/identity/backend_mongo"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_svc/identity_proto"
	"github.com/themakers/identity/mock/identity_mock_oauth2"
	"github.com/themakers/identity/mock/identity_mock_regular"
	"github.com/themakers/identity/mock/verifier_mock_regular"
	"github.com/themakers/identity/verifier_password"
	"github.com/themakers/session"
	"github.com/themakers/session/session_redis"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"net"
	"testing"
	"time"
)

func serveIdentitySvc(ctx context.Context, t *testing.T, verifiers ...identity.Verifier) (port int) {

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	backend, err := backend_mongo.New(backend_mongo.Options{
		DBName:           "identity_test",
		CollectionPrefix: "idn",
		Address:          "127.0.0.1",
		Port:             27017,

		Testing: true,
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	ssp := session_redis.NewStoragePool(session_redis.Options{
		Address:"127.0.0.1:6379",
		Namespace: "identity_test_session",

		Testing: true,
	})

	idenSvc, err := New(backend, &session.Manager{
		Storage:         ssp,
		DefaultLifetime: 5 * time.Second,
	}, []identity.Identity{
		identity_mock_regular.New(),
		identity_mock_oauth2.New(),
	}, verifiers)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	{ // gRPC server
		server := grpc.NewServer()
		idenSvc.Register(server, server)

		go func() {
			<-ctx.Done()
			server.Stop()
		}()

		go func() {
			if err := server.Serve(lis); err != nil {
				t.Error(err)
				t.FailNow()
			}
		}()
	}

	return lis.Addr().(*net.TCPAddr).Port
}

type User struct {
	ID string
	//SessionToken string
	MD metadata.MD
}

func (u *User) Context(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, u.MD)
}

func (u *User) Trailer() grpc.CallOption {
	return grpc.Trailer(&u.MD)
}

func TestSpec(t *testing.T) {
	t.Log("test started")

	Convey("Given some integer with a starting value", t, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var (
			regularVerificationData = struct {
				Code     string
				Identity string
			}{}
			//staticVerificationData = struct {
			//	Login string
			//	Pass  string
			//}{}
		)

		client := (func() identity_proto.IdentityClient {
			port := serveIdentitySvc(ctx, t, verifier_mock_regular.New(func(idn, code string) {
				regularVerificationData.Code = code
				regularVerificationData.Identity = idn
			}), verifier_password.New())

			cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
			if err != nil {
				panic(err)
			}

			return identity_proto.NewIdentityClient(cc)
		})()

		user := &User{}

		Convey("When the integer is incremented", func() {

			vdet, err := client.ListSupportedIdentitiesAndVerifiers(
				user.Context(ctx),
				&identity_proto.ListSupportedIdentitiesAndVerifiersReq{},
				user.Trailer())
			So(err, ShouldBeNil)

			for _, idn := range vdet.IdentitiyNames {
				t.Logf("IDN: %s", idn)
			}
			for _, vr := range vdet.Verifiers {
				t.Logf("IDN: %#v", vr)
			}

		})
	})
}
