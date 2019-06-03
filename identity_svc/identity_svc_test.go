package identity_svc

import (
	"context"
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/themakers/identity/backend_mongo"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_svc/identity_proto"
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

////////////////////////////////////////////////////////////////
//// Testing Server
////

func serveIdentitySvcAndGetClient(ctx context.Context, t *testing.T, verifiers ...identity.Verifier) (client identity_proto.IdentityClient) {
	port := serveIdentitySvc(ctx, t, verifiers...)

	cc, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithInsecure())
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

	ssp := session_redis.NewStoragePool(session_redis.Options{
		Address:   "127.0.0.1:6379",
		Namespace: "identity_test_session",

		Testing: true,
	})

	idenSvc, err := New(backend, &session.Manager{
		Storage:         ssp,
		DefaultLifetime: 5 * time.Second,
	}, []identity.Identity{
		identity_mock_regular.New(),
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
						// FIXME
						//So(status.Authenticated, ShouldBeNil)
						//So(status.Authenticating, ShouldNotBeNil)

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

						Convey("SignIn", testSignIn(ctx, t, state))
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
							_, err := state.client.Verify(
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
						So(err, ShouldBeNil)
						So(status.Authenticated, ShouldBeNil)
						So(status.Authenticating, ShouldNotBeNil)

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
