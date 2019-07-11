package identity_svc

import (
	"context"
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/themakers/foundation/default_cookie"
	"github.com/themakers/foundation/grpcx/grpc_default"
	"github.com/themakers/identity/backend_mongo"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_svc/identity_proto"
	"github.com/themakers/identity/mock/identity_mock_regular"
	"github.com/themakers/identity/mock/verifier_mock_regular"
	"github.com/themakers/identity/verifier_password"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"net"
	"testing"
	"time"
)

////////////////////////////////////////////////////////////////
//// Testing Server
////

func serveIdentitySvcAndGetClient(ctx context.Context, t *testing.T, verifiers ...identity.Verifier) (client identity_proto.IdentityClient) {
	port := serveIdentitySvc(ctx, t, verifiers...)

	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port),
		grpc.WithInsecure(),
		grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			err := invoker(ctx, method, req, reply, cc, opts...)
			//md, _ := metadata.FromIncomingContext(ctx)
			//log.Println("MD", md)
			return err
		}))
	if err != nil {
		panic(err)
	}

	return identity_proto.NewIdentityClient(cc)
}

func serveIdentitySvc(ctx context.Context, t *testing.T, verifiers ...identity.Verifier) (port int) {

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	backend, err := backend_mongo.New(backend_mongo.Options{
		DBName:           "identity_test",
		CollectionPrefix: "idn_",
		URI:              "mongodb://localhost:27017/?replicaSet=rs0",
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	if err := backend.Cleanup(ctx); err != nil {
		t.Error(err)
		t.FailNow()
	}

	log, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	idenSvc, err := New(backend, default_cookie.DefaultCookieKey, []identity.Identity{
		identity_mock_regular.New(),
	}, verifiers)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	{ // gRPC server
		server := grpc.NewServer(grpc_default.DefaultServerOptions(log, "this is", "madness", func(rec interface{}) *status.Status {
			var (
				code    codes.Code
				message string
			)

			if err, ok := rec.(error); ok {
				code = codes.Internal
				message = fmt.Sprintf("%s", err.Error())
			} else {
				code = codes.Internal
				message = fmt.Sprintf("%v", rec)
			}

			return status.New(code, message)
		}, nil).Pack()...)
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

////////////////////////////////////////////////////////////////
//// User
////

type User struct {
	MD metadata.MD
}

func (u *User) Context(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, u.MD)
}

func (u *User) Trailer() grpc.CallOption {
	return grpc.Trailer(&u.MD)
}

////////////////////////////////////////////////////////////////
//// Spec
////

type State struct {
	regularVerificationData struct {
		Code     string
		Identity string
	}
	client identity_proto.IdentityClient
	user   *User
}

func TestSpec(t *testing.T) {
	Convey("Starting and initializing identity service", t, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		state := &State{
			user: &User{},
		}

		state.client = serveIdentitySvcAndGetClient(ctx, t, verifier_mock_regular.New(func(idn, code string) {
			state.regularVerificationData.Code = code
			state.regularVerificationData.Identity = idn
		}), verifier_password.New())

		Convey("Getting list of available identities and verifiers", func() {
			// TODO
			_, err := state.client.ListSupportedIdentitiesAndVerifiers(
				state.user.Context(ctx),
				&identity_proto.ListSupportedIdentitiesAndVerifiersReq{},
				state.user.Trailer())
			So(err, ShouldBeNil)
			log.Println("MD", state.user)
		})

		Convey("SignUp", testSignUp(ctx, t, state))
	})
}

func testSignUp(ctx context.Context, t *testing.T, state *State) func() {
	return func() {
		Convey("Should be unauthenticated", func() {
			status, err := state.client.CheckStatus(
				state.user.Context(ctx),
				&identity_proto.StatusReq{},
				state.user.Trailer())
			So(err, ShouldBeNil)
			So(status.Authenticating, ShouldBeNil)
			So(status.Authenticated, ShouldBeNil)

			//Convey("Should be unauthenticated", func() {})

			Convey("Start sign up process", func() {
				status, err := state.client.StartSignUp(
					state.user.Context(ctx),
					&identity_proto.StartSignUpReq{},
					state.user.Trailer())
				So(err, ShouldBeNil)
				So(status.Authenticating, ShouldNotBeNil)
				So(status.Authenticated, ShouldBeNil)
				{
					So(status.Authenticating.CompletedFactors, ShouldHaveLength, 0)
					So(status.Authenticating.Objective, ShouldHaveSameTypeAs, &identity_proto.StatusAuthenticating_SignUp{})
					So(status.Authenticating.RemainingFactors, ShouldEqual, 1)
				}

				Convey("Initiate regular verification", func() {
					So(state.regularVerificationData.Identity, ShouldEqual, "")
					So(state.regularVerificationData.Code, ShouldEqual, "")
					_, err := state.client.Start(
						state.user.Context(ctx),
						&identity_proto.StartReq{
							VerifierName: verifier_mock_regular.New(nil).Info().Name,
							Identity:     "hellokitty",
						},
						state.user.Trailer())
					So(err, ShouldBeNil)
					So(state.regularVerificationData.Identity, ShouldEqual, "hellokitty")
					So(state.regularVerificationData.Code, ShouldNotEqual, "")

					Convey("Provide wrong verification code", func() {
						_, err := state.client.Verify(
							state.user.Context(ctx),
							&identity_proto.VerifyReq{
								VerifierName:     verifier_mock_regular.New(nil).Info().Name,
								Identity:         "hellokitty",
								VerificationCode: "wrong" + state.regularVerificationData.Code,
							},
							state.user.Trailer())
						So(err, ShouldNotBeNil)
						So(err.Error(), ShouldContainSubstring, identity.ErrVerificationCodeMismatch.Error())
						So(status.Authenticated, ShouldBeNil)
						So(status.Authenticating, ShouldNotBeNil)

						Convey("Then successfully complete it", func() {
							status, err := state.client.Verify(
								state.user.Context(ctx),
								&identity_proto.VerifyReq{
									VerifierName:     verifier_mock_regular.New(nil).Info().Name,
									Identity:         "hellokitty",
									VerificationCode: state.regularVerificationData.Code,
								},
								state.user.Trailer())
							So(err, ShouldBeNil)
							So(status.Authenticating, ShouldBeNil)
							So(status.Authenticated, ShouldNotBeNil)
							So(status.Authenticated.User, ShouldNotEqual, "")

							Convey("Attach", testAttach(ctx, t, state))
						})
					})
				})
			})
		})
	}
}

func testAttach(ctx context.Context, t *testing.T, state *State) func() {
	return func() {
		Convey("Should be authenticated", func() {
			status, err := state.client.CheckStatus(
				state.user.Context(ctx),
				&identity_proto.StatusReq{},
				state.user.Trailer())
			So(err, ShouldBeNil)
			So(status.Authenticating, ShouldBeNil)
			So(status.Authenticated, ShouldNotBeNil)

			Convey("Starting Attach process", func() {
				status, err := state.client.StartAttach(
					state.user.Context(ctx),
					&identity_proto.StartAttachReq{},
					state.user.Trailer())
				So(err, ShouldBeNil)
				So(status.Authenticating, ShouldNotBeNil)
				So(status.Authenticated, ShouldNotBeNil)

				Convey("Start attaching password", func() {
					password := "secret"
					_, err := state.client.Start(
						state.user.Context(ctx),
						&identity_proto.StartReq{
							VerifierName: verifier_password.New().Info().Name,
							Args: identity.M{
								"password": password,
							},
						},
						state.user.Trailer())
					So(err, ShouldBeNil)

					Convey("Try to verify wrong password", func() {
						status, err := state.client.Verify(
							state.user.Context(ctx),
							&identity_proto.VerifyReq{
								VerifierName:     verifier_password.New().Info().Name,
								VerificationCode: "wrong" + password,
							},
							state.user.Trailer())
						So(err, ShouldNotBeNil)
						So(err.Error(), ShouldContainSubstring, identity.ErrVerificationCodeMismatch.Error())
						// FIXME
						So(status, ShouldBeNil)
						//So(status.Authenticated, ShouldBeNil)
						//So(status.Authenticating, ShouldNotBeNil)

						Convey("Then verify new password", func() {
							status, err := state.client.Verify(
								state.user.Context(ctx),
								&identity_proto.VerifyReq{
									VerifierName:     verifier_password.New().Info().Name,
									VerificationCode: password,
								},
								state.user.Trailer())
							So(err, ShouldBeNil)
							So(status.Authenticating, ShouldBeNil)
							So(status.Authenticated, ShouldNotBeNil)

							Convey("Check your active identities and verifiers now", func() {
								list, err := state.client.ListMyIdentitiesAndVerifiers(
									state.user.Context(ctx),
									&identity_proto.ListMyIdentitiesAndVerifiersReq{},
									state.user.Trailer())
								So(err, ShouldBeNil)
								t.Logf("%#v", list)
								So(list.Identities, ShouldHaveLength, 1)
								So(list.Identities[0].Name, ShouldEqual, identity_mock_regular.New().Info().Name)
								So(list.Identities[0].Identity, ShouldEqual, "hellokitty")
								So(list.Verifiers, ShouldContain, verifier_password.New().Info().Name)

								Convey("SignIn", testSignIn(ctx, t, state))
							})
						})
					})
				})
			})
		})
	}
}

func testSignIn(ctx context.Context, t *testing.T, state *State) func() {
	return func() {
		Convey("Should log out", func() {
			// FIXME
			state.user.MD = nil

			Convey("And become nobody now", func() {
				status, err := state.client.CheckStatus(
					state.user.Context(ctx),
					&identity_proto.StatusReq{},
					state.user.Trailer())
				So(err, ShouldBeNil)
				So(status.Authenticating, ShouldBeNil)
				So(status.Authenticated, ShouldBeNil)

				Convey("Starting SignIn process", func() {
					idn := "hellokitty"
					status, err := state.client.StartSignIn(
						state.user.Context(ctx),
						&identity_proto.StartSignInReq{},
						state.user.Trailer())
					So(err, ShouldBeNil)
					So(status.Authenticating, ShouldNotBeNil)
					So(status.Authenticated, ShouldBeNil)

					Convey("SignIn using regular verifier", func() {
						state.regularVerificationData.Identity = ""
						state.regularVerificationData.Code = ""
						So(state.regularVerificationData.Identity, ShouldEqual, "")
						So(state.regularVerificationData.Code, ShouldEqual, "")
						_, err := state.client.Start(
							state.user.Context(ctx),
							&identity_proto.StartReq{
								VerifierName: verifier_mock_regular.New(nil).Info().Name,
								Identity:     idn,
							},
							state.user.Trailer())
						So(err, ShouldBeNil)
						So(state.regularVerificationData.Identity, ShouldEqual, idn)
						So(state.regularVerificationData.Code, ShouldNotEqual, "")

						Convey("Provide wrong verification code", func() {
							status, err := state.client.Verify(
								state.user.Context(ctx),
								&identity_proto.VerifyReq{
									VerifierName:     verifier_mock_regular.New(nil).Info().Name,
									Identity:         idn,
									VerificationCode: "wrong" + state.regularVerificationData.Code,
								},
								state.user.Trailer())
							So(err, ShouldNotBeNil)
							So(err.Error(), ShouldContainSubstring, identity.ErrVerificationCodeMismatch.Error())
							// FIXME
							So(status, ShouldBeNil)
							//So(status.Authenticated, ShouldBeNil)
							//So(status.Authenticating, ShouldNotBeNil)

							Convey("Then successfully complete it", func() {
								status, err := state.client.Verify(
									state.user.Context(ctx),
									&identity_proto.VerifyReq{
										VerifierName:     verifier_mock_regular.New(nil).Info().Name,
										Identity:         idn,
										VerificationCode: state.regularVerificationData.Code,
									},
									state.user.Trailer())
								So(err, ShouldBeNil)
								So(status.Authenticating, ShouldBeNil)
								So(status.Authenticated, ShouldNotBeNil)
								So(status.Authenticated.User, ShouldNotEqual, "")
							})
						})
					})

					// TODO Test without identity first, to ensure error reporting correctness
					Convey("SignIn using static password verifier with incorrect password", func() {
						password := "secret"
						status, err := state.client.Verify(
							state.user.Context(ctx),
							&identity_proto.VerifyReq{
								VerifierName:     verifier_password.New().Info().Name,
								VerificationCode: "wrong" + password,
								IdentityName:     identity_mock_regular.New().Info().Name,
								Identity:         idn,
							},
							state.user.Trailer())
						So(err, ShouldNotBeNil)
						So(err.Error(), ShouldContainSubstring, identity.ErrVerificationCodeMismatch.Error())
						// FIXME
						So(status, ShouldBeNil)
						//So(status.Authenticated, ShouldBeNil)
						//So(status.Authenticating, ShouldNotBeNil)

						Convey("Then provide correct password", func() {
							status, err := state.client.Verify(
								state.user.Context(ctx),
								&identity_proto.VerifyReq{
									VerifierName:     verifier_password.New().Info().Name,
									VerificationCode: password,
									IdentityName:     identity_mock_regular.New().Info().Name,
									Identity:         idn,
								},
								state.user.Trailer())
							So(err, ShouldBeNil)
							So(status.Authenticating, ShouldBeNil)
							So(status.Authenticated, ShouldNotBeNil)
							So(status.Authenticated.User, ShouldNotEqual, "")
						})
					})
				})
			})
		})
	}
}
