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
	"github.com/themakers/identity/mock/verifier_mock_oauth2"
	"github.com/themakers/identity/mock/verifier_mock_regular"
	"github.com/themakers/identity/mock/verifier_mock_static"
	"github.com/themakers/identity/verifier_password"
	"github.com/themakers/session"
	"github.com/themakers/session/session_redis"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"log"
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

	idenSvc, err := New(backend, &session.Manager{Storage: stPoll, DefaultLifetime: 5}, []identity.Identity{identity_mock_regular.New(), identity_mock_oauth2.New()}, verifiers)

	idenSvc.Register(server, server)

	go func() {
		if err := server.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return lis.Addr().(*net.TCPAddr).Port
}

func Test1FRegular(t *testing.T) {
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

	Convey("Test list of identities", t, func() {
		var trailer metadata.MD
		idn, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		So(idn.IdentitiyNames, ShouldResemble, []string{"mock_identity_regular", "mock_identity_oauth2"})
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
		vd := map[string]string{}
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
		vd := make(map[string]string)
		vd["mock_identity"] = ""
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
		vd := make(map[string]string)
		vd["mock_identity_regular"] = ""
		svResp, err := client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "mock_regular", Identity: "79991112233", VerificationData: vd}, grpc.Trailer(&trailer))
		So(svResp.AuthenticationID, ShouldEqual, trailer[SessionTokenName][0])

		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: regularVerificationData.Code, AuthenticationID: svResp.AuthenticationID, Identity: "79991112233"})

		if err != nil {
			panic(err)
		}

		auth, err := client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, false)
	})
}

func Test1FOauth(t *testing.T) {
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
	oauth2VerificationData := struct {
		Identity string
	}{}

	// создаем новый сервер и сохранеяем порт, на котором он работает
	port := serve(ctx, verifier_mock_regular.New(func(idn, code string) {
		regularVerificationData.Code = code
		regularVerificationData.Identity = idn
	}), verifier_mock_static.New(func(login, pass string) {
		staticVerificationData.Login = login
		staticVerificationData.Pass = pass
	}), verifier_mock_oauth2.New(func(idn string) {
		oauth2VerificationData.Identity = idn
	}))

	//
	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	client := identity_proto.NewIdentityClient(cc)
	Convey("Test list of identities", t, func() {
		var trailer metadata.MD
		idn, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		So([]string{idn.Verifiers[0].Name, idn.Verifiers[1].Name, idn.Verifiers[2].Name}, ShouldResemble, []string{"mock_regular", "mock_static", "mock_oauth2"})
	})

	Convey("Test two factor auth - regular/oauth2", t, func() {
		var trailer metadata.MD
		_, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		ctx = metadata.AppendToOutgoingContext(ctx, SessionTokenName, trailer[SessionTokenName][0])
		_, err = client.StartAuthentication(ctx, &identity_proto.StartAuthenticationReq{VerifierName: "mock_oauth2"}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_oauth2", VerificationCode: "asdas"})
		if err != nil {
			panic(err)
		}
		auth, err := client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, false)
	})
}

func Test2FOAuth2Regular(t *testing.T) {
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
	oauth2VerificationData := struct {
		Identity string
	}{}

	// создаем новый сервер и сохранеяем порт, на котором он работает
	port := serve(ctx, verifier_mock_regular.New(func(idn, code string) {
		regularVerificationData.Code = code
		regularVerificationData.Identity = idn
	}), verifier_mock_static.New(func(login, pass string) {
		staticVerificationData.Login = login
		staticVerificationData.Pass = pass
	}), verifier_mock_oauth2.New(func(idn string) {
		oauth2VerificationData.Identity = idn
	}))

	//
	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	client := identity_proto.NewIdentityClient(cc)
	Convey("Test list of identities", t, func() {
		var trailer metadata.MD
		idn, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		So(idn.IdentitiyNames, ShouldResemble, []string{"mock_identity_regular", "mock_identity_oauth2"})

		So([]string{idn.Verifiers[0].Name, idn.Verifiers[1].Name, idn.Verifiers[2].Name}, ShouldResemble, []string{"mock_regular", "mock_static", "mock_oauth2"})

	})

	Convey("Test two factor auth - regular/oauth2", t, func() {
		var trailer metadata.MD
		_, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		ctx = metadata.AppendToOutgoingContext(ctx, SessionTokenName, trailer[SessionTokenName][0])
		_, err = client.StartAuthentication(ctx, &identity_proto.StartAuthenticationReq{VerifierName: "mock_oauth2"}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		vd := make(map[string]string)
		vd["mock_identity"] = ""
		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_oauth2", VerificationCode: "asdas"})

		if err != nil {
			panic(err)
		}
		auth, err := client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		_, err = client.ListMyIdentitiesAndVerifiers(ctx, &identity_proto.MyVerifiersDetailRequest{}, grpc.Trailer(&trailer))
		_, err = client.StartAuthentication(ctx, &identity_proto.StartAuthenticationReq{VerifierName: "mock_regular"}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		vd = make(map[string]string)
		vd["mock_identity"] = ""
		svResp, err := client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "mock_regular", Identity: "7999332211", VerificationData: vd}, grpc.Trailer(&trailer))
		So(svResp.AuthenticationID, ShouldEqual, trailer[SessionTokenName][0])

		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: regularVerificationData.Code, AuthenticationID: svResp.AuthenticationID, Identity: "7999332211"})

		if err != nil {
			panic(err)
		}

		auth, err = client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, true)
	})
}

func Test2FRegularOAuth2(t *testing.T) {
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
	oauth2VerificationData := struct {
		Identity string
	}{}

	// создаем новый сервер и сохранеяем порт, на котором он работает
	port := serve(ctx, verifier_mock_regular.New(func(idn, code string) {
		regularVerificationData.Code = code
		regularVerificationData.Identity = idn
	}), verifier_mock_static.New(func(login, pass string) {
		staticVerificationData.Login = login
		staticVerificationData.Pass = pass
	}), verifier_mock_oauth2.New(func(idn string) {
		oauth2VerificationData.Identity = idn
	}))

	//
	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	client := identity_proto.NewIdentityClient(cc)
	Convey("Test list of identities", t, func() {
		var trailer metadata.MD
		idn, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		So(idn.IdentitiyNames, ShouldResemble, []string{"mock_identity_regular", "mock_identity_oauth2"})

		So([]string{idn.Verifiers[0].Name, idn.Verifiers[1].Name, idn.Verifiers[2].Name}, ShouldResemble, []string{"mock_regular", "mock_static", "mock_oauth2"})

	})

	Convey("Test two factor auth - regular/oauth2", t, func() {
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
		vd := make(map[string]string)
		vd["mock_identity_regular"] = ""
		svResp, err := client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "mock_regular", Identity: "7999332211", VerificationData: vd}, grpc.Trailer(&trailer))
		So(svResp.AuthenticationID, ShouldEqual, trailer[SessionTokenName][0])
		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: regularVerificationData.Code, AuthenticationID: svResp.AuthenticationID, Identity: "7999332211"})
		if err != nil {
			panic(err)
		}
		auth, err := client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		_, err = client.ListMyIdentitiesAndVerifiers(ctx, &identity_proto.MyVerifiersDetailRequest{}, grpc.Trailer(&trailer))
		_, err = client.StartAuthentication(ctx, &identity_proto.StartAuthenticationReq{VerifierName: "mock_oauth2"}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		//vd["mock_identity"] = ""
		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_oauth2", VerificationCode: "asdas"})
		if err != nil {
			panic(err)
		}
		auth, err = client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, true)
	})
}

func Test2FRegularStatic(t *testing.T) {
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
	oauth2VerificationData := struct {
		Identity string
	}{}

	// создаем новый сервер и сохранеяем порт, на котором он работает
	port := serve(ctx, verifier_mock_regular.New(func(idn, code string) {
		regularVerificationData.Code = code
		regularVerificationData.Identity = idn
	}), verifier_mock_static.New(func(login, pass string) {
		staticVerificationData.Login = login
		staticVerificationData.Pass = pass
	}), verifier_mock_oauth2.New(func(idn string) {
		oauth2VerificationData.Identity = idn
	}), verifier_password.New())

	//
	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	client := identity_proto.NewIdentityClient(cc)
	Convey("Test two factor auth - regular/static", t, func() {
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
		vd := map[string]string{}
		svResp, err := client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "mock_regular", Identity: "79992233111", VerificationData: vd}, grpc.Trailer(&trailer))
		So(svResp.AuthenticationID, ShouldEqual, trailer[SessionTokenName][0])
		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: regularVerificationData.Code, AuthenticationID: svResp.AuthenticationID, Identity: "79992233111"})

		if err != nil {
			panic(err)
		}
		_, err = client.ListMyIdentitiesAndVerifiers(ctx, &identity_proto.MyVerifiersDetailRequest{}, grpc.Trailer(&trailer))
		res, err := client.InitializeStaticVerifier(ctx, &identity_proto.InitializeStaticVerifierReq{VerifierName: "Login", InitializationData: map[string]string{"micresh": "wepo23nri"}}, grpc.Trailer(&trailer))
		log.Println(res)
		if err != nil {
			log.Println(res)
			panic(err)
		}
		// test false password and true login
		_, err = client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "Login", Identity: "", VerificationData: map[string]string{"micresh": "wepo23nri123"}})
		auth, err := client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, false)
		// test true password and false login
		_, err = client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "Login", Identity: "", VerificationData: map[string]string{"miccresh": "wepo23nri"}})
		auth, err = client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, false)
		// test true password and true login
		_, err = client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "Login", Identity: "", VerificationData: map[string]string{"micresh": "wepo23nri"}})
		auth, err = client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, true)
	})
}

func Test2FStaticRegular(t *testing.T) {
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
	oauth2VerificationData := struct {
		Identity string
	}{}

	// создаем новый сервер и сохранеяем порт, на котором он работает
	port := serve(ctx, verifier_mock_regular.New(func(idn, code string) {
		regularVerificationData.Code = code
		regularVerificationData.Identity = idn
	}), verifier_mock_static.New(func(login, pass string) {
		staticVerificationData.Login = login
		staticVerificationData.Pass = pass
	}), verifier_mock_oauth2.New(func(idn string) {
		oauth2VerificationData.Identity = idn
	}), verifier_password.New())

	//
	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
	if err != nil {
		panic(err)
	}
	client := identity_proto.NewIdentityClient(cc)
	Convey("Test two factor auth - regular/static", t, func() {
		var trailer metadata.MD
		_, err := client.ListIdentitiesAndVerifiers(ctx, &identity_proto.VerifiersDetailsRequest{}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		ctx = metadata.AppendToOutgoingContext(ctx, SessionTokenName, trailer[SessionTokenName][0])
		_, err = client.StartAuthentication(ctx, &identity_proto.StartAuthenticationReq{VerifierName: "Login"}, grpc.Trailer(&trailer))
		if err != nil {
			panic(err)
		}
		vd := map[string]string{}
		_, err = client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "Login", Identity: "", VerificationData: map[string]string{"micresh": "wepo23nri"}})
		svResp, err := client.StartVerification(ctx, &identity_proto.StartVerificationReq{VerifierName: "mock_regular", Identity: "79992233111", VerificationData: vd}, grpc.Trailer(&trailer))
		// test correct code and incorrect identity
		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: regularVerificationData.Code, AuthenticationID: svResp.AuthenticationID, Identity: "79998233111"})
		if err != nil {
			panic(err)
		}
		auth, err := client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, false)
		// test incorrect code and correct identity
		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: "12345", AuthenticationID: svResp.AuthenticationID, Identity: "79992233111"})
		if err != nil {
			panic(err)
		}
		auth, err = client.CheckStatus(ctx, &identity_proto.StatusReq{})
		if err != nil {
			panic(err)
		}
		So(auth.Authenticated, ShouldEqual, false)

		// test correct identity and code
		_, err = client.Verify(ctx, &identity_proto.VerifyReq{VerifierName: "mock_regular", VerificationCode: regularVerificationData.Code, AuthenticationID: svResp.AuthenticationID, Identity: "79992233111"})
		if err != nil {
			panic(err)
		}
		auth, err = client.CheckStatus(ctx, &identity_proto.StatusReq{})
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
