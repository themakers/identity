package identity_svc

import (
	"context"
	"fmt"
	"github.com/smartystreets/goconvey/convey"
	"github.com/themakers/identity/backend_mongo"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_email"
	"github.com/themakers/identity/identity_phone"
	"github.com/themakers/identity/identity_svc/identity_proto"
	"github.com/themakers/session"
	"google.golang.org/grpc"
	"net"
	"testing"
)

/*
func TestPublicIdentityService_ListIdentitiesAndVerifiers(t *testing.T) {
	testidn := identity.IdentityData{Name:"email", Identity:"test@test.test"}
	convey.Convey("Simple testing", func() {
		convey.So(testidn, convey.ShouldEqual, testidn)
	})
}
*/
func serve(ctx context.Context) (port int) {
	server := grpc.NewServer()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	backend, err := backend_mongo.New("identity", "idn", "127.0.0.1", 27017)

	idenSvc, err := New(backend, &session.Manager{}, []identity.Identity{
		identity_phone.New(), identity_email.New(),
	}, []identity.Verifier{})

	idenSvc.Register(server, server)

	go func() {
		if err := server.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return lis.Addr().(*net.TCPAddr).Port
}

func TestIntt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	<-ctx.Done()

	port := serve(ctx)

	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	client := identity_proto.NewIdentityClient(cc)
	iden, err := client.ListIdentitiesAndVerifiers(ctx, nil)

	convey.Convey("Test list of identities", t, func() {
		convey.So(iden.Identities, convey.ShouldEqual, []string{"phone", "email"})
	})
	//TODO realise test for verifier list
	/*
		convey.Convey("Test of list verifiers", t, func() {
			convey.So(iden.Verifiers, convey.ShouldEqual, [])
		})*/
}
