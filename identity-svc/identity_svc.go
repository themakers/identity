package identity_svc

import (
	"context"
	"github.com/themakers/session"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity-svc/identity_proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

//go:generate protoc -I ../identity-proto ../identity-proto/identity.proto --go_out=plugins=grpc:./identity_proto

const SessionTokenName = "session_token"

type IdentitySvc struct {
	mgr *identity.Manager
}

func New(backend identity.Backend, sessMgr *session.Manager, providers ...identity.Provider) (*IdentitySvc, error) {
	is := &IdentitySvc{}

	if mgr, err := identity.New(
		backend,
		sessMgr,
		providers...,
	); err != nil {
		return nil, err
	} else {
		is.mgr = mgr
	}

	return is, nil
}

func (is *IdentitySvc) Register(public, private *grpc.Server) {
	identity_proto.RegisterAuthenticationServer(public, &PublicIdentityService{
		is: is,
	})
}

////////////////////////////////////////////////////////////////
//// Helpers
////

func GetSessionToken(ctx context.Context) (token string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	if at := md.Get(SessionTokenName); len(at) != 0 {
		return at[0]
	} else {
		return ""
	}
}

////////////////////////////////////////////////////////////////
//// PublicIdentityService
////

type PublicIdentityService struct {
	is *IdentitySvc
}

func (pis *PublicIdentityService) ListProviders(ctx context.Context, q *identity_proto.ProviderDetailsReq) (*identity_proto.ProviderDetailsResp, error) {
	resp := &identity_proto.ProviderDetailsResp{}

	for _, prov := range pis.is.mgr.ListProviders() {
		resp.Providers = append(resp.Providers, &identity_proto.ProviderDetails{
			Name:          prov.Name,
			SupportType1:  prov.SupportType1,
			SupportType2:  prov.SupportType2,
			SupportOAuth2: prov.SupportOAuth2,
		})
	}

	return resp, nil
}

func (pis *PublicIdentityService) Type1Request(ctx context.Context, q *identity_proto.Type1VerificationReq) (*identity_proto.Type1VerificationDirections, error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	verificationID, target, securityCode, err := sess.StartType1Verification(ctx, q.Provider, q.Identity)
	if err != nil {
		return nil, err
	}

	return &identity_proto.Type1VerificationDirections{
		VerificationID: verificationID,
		Target:         target,
		SecurityCode:   securityCode,
	}, nil
}

func (pis *PublicIdentityService) Type1Result(ctx context.Context, q *identity_proto.Type1ResultRequest) (*identity_proto.Type1ResultResp, error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	err := sess.AwaitType1Result(ctx, q.VerificationID)
	if err != nil {
		return nil, err
	}

	// FIXME Handle user id

	return &identity_proto.Type1ResultResp{Error: ""}, nil
}

func (pis *PublicIdentityService) Type2Request(ctx context.Context, q *identity_proto.Type2VerificationReq) (*identity_proto.Type2VerificationResp, error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	verificationID, err := sess.StartType2Verification(ctx, q.Provider, q.Identity)
	if err != nil {
		return nil, err
	}

	return &identity_proto.Type2VerificationResp{
		VerificationID: verificationID,
	}, nil
}

func (pis *PublicIdentityService) Type2Verify(ctx context.Context, q *identity_proto.Type2VerifyReq) (*identity_proto.Type2ResultResp, error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	err := sess.Type2Verify(ctx, q.VerificationID, q.SecurityCode)
	if err != nil {
		return nil, err
	}

	// FIXME Handle user id

	return &identity_proto.Type2ResultResp{
		Error: "",
	}, nil
}

func (pis *PublicIdentityService) OAuth2Verify(ctx context.Context, q *identity_proto.OAuth2Req) (*identity_proto.OAuth2VerifyResp, error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	err := sess.OAuth2Verify(ctx, q.Provider, q.Code)
	if err != nil {
		return nil, err
	}

	// FIXME Handle user id

	return &identity_proto.OAuth2VerifyResp{
		Error: "",
	}, nil
}

////////////////////////////////////////////////////////////////
//// PrivateAuthenticationService
////

type PrivateAuthenticationService struct {
	auth *IdentitySvc
}
