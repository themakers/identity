package identity_svc

import (
	"context"
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/themakers/identity/backend_mongo"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_svc/identity_proto"
	"github.com/themakers/identity/mock/identity_mock"
	"github.com/themakers/identity/mock/verifier_mock_regular"
	"github.com/themakers/identity/mock/verifier_mock_static"
	"github.com/themakers/session"
	"github.com/themakers/session/session_redis"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"net"

	"testing"
)

type request struct{}

func serve(ctx context.Context, verifiers ...identity.Verifier) (port int) {
	server := grpc.NewServer()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	backend, err := backend_mongo.New("identity_test", "idn", "127.0.0.1", 27017)

	stPoll := session_redis.NewStoragePool("127.0.0.1:6379", "redis")

	idenSvc, err := New(backend, &session.Manager{Storage: stPoll, DefaultLifetime: 5}, []identity.Identity{identity_mock.New()}, verifiers)

	idenSvc.Register(server, server)

	go func() {
		if err := server.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return lis.Addr().(*net.TCPAddr).Port
}

func Test1F(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	select {
	case <-ctx.Done():
		return
	default:
	}

	regularVerificationData := struct {
		Code     string
		Identity string
	}{}

	staticVerificationData := struct {
		Login string
		Pass  string
	}{}

	// создаем новый сервер и сохранеяем порт, на котором он работает
	port := serve(ctx, verifier_mock_regular.New(func(idn, code string) {
		regularVerificationData.Code = code
		regularVerificationData.Identity = idn
	}), verifier_mock_static.New(func(login, pass string) {
		staticVerificationData.Login = login
		staticVerificationData.Pass = pass
	}))

	//
	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	client := identity_proto.NewIdentityClient(cc)

	// стартуем тестирование
	/*
		Convey("Test list of identities", t, func() {
			var trailer metadata.MD
			idn, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
			if err != nil {
				panic(err)
			}
			So(idn.IdentitiyNames, ShouldResemble, []string{"mock_identity"})
			So(idn.Verifiers[0].Name, ShouldEqual, "mock_regular")

		})

		Convey("Test user start authentication", t, func() {
			var trailer metadata.MD
			_, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
			ctx = metadata.AppendToOutgoingContext(ctx, SessionTokenName, trailer[SessionTokenName][0])
			if err != nil {
				panic(err)
			}
			resAuth, err := client.StartAuthentication(ctx, &identity_proto.StartAuthenticationReq{}, grpc.Trailer(&trailer))
			if err != nil {
				panic(err)
			}
			So(resAuth.AuthenticationSessionExist, ShouldEqual, true)
		})

		Convey("Test user verification", t, func() {
			var trailer metadata.MD
			_, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
			if err != nil {
				panic(err)
			}
			ctx = metadata.AppendToOutgoingContext(ctx, SessionTokenName, trailer[SessionTokenName][0])
			_, err = client.StartAuthentication(ctx, &identity_proto.StartAuthenticationReq{}, grpc.Trailer(&trailer))
			if err != nil {
				panic(err)
			}
			vd := make(map[string][]byte)
			vd["mock_identity"] = []byte{}
			svResp, err := client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "mock_regular", Identity: "79991112233", VerificationData: vd})
			So(svResp.AuthenticationID, ShouldEqual, trailer[SessionTokenName][0])

		})

		Convey("Test user verify", t, func() {
			var trailer metadata.MD
			_, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
			if err != nil {
				panic(err)
			}
			ctx = metadata.AppendToOutgoingContext(ctx, SessionTokenName, trailer[SessionTokenName][0])
			_, err = client.StartAuthentication(ctx, &identity_proto.StartAuthenticationReq{VerifierName: "mock_regular"}, grpc.Trailer(&trailer))
			if err != nil {
				panic(err)
			}
			vd := make(map[string][]byte)
			vd["mock_identity"] = []byte{}
			svResp, err := client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "mock_regular", Identity: "79991112233", VerificationData: vd}, grpc.Trailer(&trailer))
			So(svResp.AuthenticationID, ShouldEqual, trailer[SessionTokenName][0])

			vRespTrue, err := client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: regularVerificationData.Code, AuthenticationID: svResp.AuthenticationID, Identity: "79991112233"})
			vRespFalse, err := client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: "1111", AuthenticationID: svResp.AuthenticationID, Identity: "79991112233"})

			if err != nil {
				panic(err)
			}
			So(vRespTrue.VerifyStatus, ShouldEqual, true)
			So(vRespFalse.VerifyStatus, ShouldEqual, false)

		})

	*/
	Convey("Test 1Factor of new user ", t, func() {

		// пользователь получает список доступных identity and verifiers
		var trailer metadata.MD
		_, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		ctx = metadata.AppendToOutgoingContext(ctx, SessionTokenName, trailer[SessionTokenName][0])
		_, err = client.StartAuthentication(ctx, &identity_proto.StartAuthenticationReq{VerifierName: "mock_regular"}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		vd := make(map[string][]byte)
		vd["mock_identity"] = []byte{}
		svResp, err := client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "mock_regular", Identity: "79991112233", VerificationData: vd}, grpc.Trailer(&trailer))

		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: regularVerificationData.Code, AuthenticationID: svResp.AuthenticationID, Identity: "79991112233"})

		if err != nil {
			panic(err)
		}

		auth, err := client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, true)
	})
}

// after get resp_1 user can switch a verification method
// test fo new user
// ListIdentitiesAndVerifiers
//// ListMyIdentitiesAndVerifiers - выбираем количество факторов
////// StartAuthentication --- Старт процесса аутентификации (список verifier, identity(auth data))
/////// Verify  <- сюда я передаю sessionid(from context), user (from session), verifierName, identity(auth data) /if user == nil -> add user
//-------------------Новый план теста
// ListIdentitiesAndVerifiers
//// StartAuthentication
///// Verify
////// ListMyIdentitesAndVerifiers
//////// Verify

// Test scenario #1 - 1F auth by regular
//// CheckStatus
////// ListIdentitiesAndVerifiers
/////// StartVerification
//////// Verify

// Test scenario #2 - 1F auth by oauth

// Test scenario #3 - 1F auth by static

// Test scenario #4 - 2F auth by regular and oauth

// Test scenario #5 - 2F auth by regular and static

// Test scenario #6 - 2F auth by oauth and regular

// Test scenario #7 - 2F auth by oauth and static

// Test scenario #8 - 2F auth by regular and oauth

// Test scenario #9 - 2F auth by regular and oauth
