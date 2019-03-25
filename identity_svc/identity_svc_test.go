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
	"github.com/themakers/identity/verifier_email"
	"github.com/themakers/session"
	"google.golang.org/grpc"
	"net"
	"testing"
)

type request struct{}

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
	// TODO incorrect usage of constructor returned panic assignment to entry in nil map
	idenSvc, err := New(backend, &session.Manager{}, []identity.Identity{identity_phone.New(), identity_email.New()}, []identity.Verifier{verifier_email.New()})

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

	select {

	case <-ctx.Done():
		panic("somthing went wrong")
	default:
	}

	// создаем новый сервер и сохранеяем порт, на котором он работает
	port := serve(ctx)
	//
	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	client := identity_proto.NewIdentityClient(cc)

	// стартуем тестирование
	convey.Convey("Test list of identities", t, func() {
		iden, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{})
		if err != nil {
			panic(err)
		}
		convey.So(iden.Identities, convey.ShouldResemble, []string{"phone", "email"})

	})
}
