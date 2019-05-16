package identity_svc

import (
	"context"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_svc/identity_proto"
	"github.com/themakers/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
)

//go:generate protoc -I ../identity-proto ../identity-proto/identity.proto --go_out=plugins=grpc:./identity_proto

const (
	SessionTokenName = "session_token"
	UserIDName       = "user_id"
)

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
	identity_proto.RegisterIdentityServer(public, &PublicIdentityService{
		is: is,
	})
	identity_proto.RegisterIdentityPrivateServer(private, &PrivateIdentityService{
		is: is,
	})
}

////////////////////////////////////////////////////////////////
//// Helpers
////

func GetSessionToken(ctx context.Context) (token string) {
	md, ok := metadata.FromIncomingContext(ctx)
	log.Println("METADATA", ok, md)
	if !ok {
		return ""
	}

	if at := md.Get(SessionTokenName); len(at) != 0 {
		return at[0]
	} else {
		return ""
	}
}

func statusError(err error) error {
	return status.Errorf(codes.Internal, "%s", err.Error())
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

	sid, uid, err := sess.Info()
	if err != nil {
		return nil, err
	}
	{
		md := make(metadata.MD)
		if sid != "" {
			md.Set(SessionTokenName, sid)
		}
		if uid != "" {
			md.Set(UserIDName, uid)
		}
		grpc.SetTrailer(ctx, md)
	}

	return &identity_proto.Type1ResultResp{
		Session: sid,
		User:    uid,
		Error:   "",
	}, nil
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

	log.Println("Type2Verify():", q)

	err := sess.Type2Verify(ctx, q.VerificationID, q.SecurityCode)
	if err != nil {
		log.Println("Type2Verify(): error 1", err)
		return nil, err
	}

	log.Println("Type2Verify(): sess info")
	sid, uid, err := sess.Info()
	if err != nil {
		log.Println("Type2Verify(): error 2", err)
		return nil, err
	}
	log.Println("Type2Verify():", sid, uid)
	{
		md := make(metadata.MD)
		if sid != "" {
			log.Println("Type2Verify(): SID", sid)
			md.Set(SessionTokenName, sid)
		}
		if uid != "" {
			log.Println("Type2Verify(): UID", uid)
			md.Set(UserIDName, uid)
		}
		if err := grpc.SetTrailer(ctx, md); err != nil {
			panic(err)
		}
	}

	log.Println("Type2Verify(): done")
	return &identity_proto.Type2ResultResp{
		Session: sid,
		User:    uid,
		Error:   "",
	}, nil
}

func (pis *PublicIdentityService) OAuth2Verify(ctx context.Context, q *identity_proto.OAuth2Req) (*identity_proto.OAuth2VerifyResp, error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	err := sess.OAuth2Verify(ctx, q.Provider, q.Code)
	if err != nil {
		return nil, err
	}

	sid, uid, err := sess.Info()
	if err != nil {
		return nil, err
	}
	{
		md := make(metadata.MD)
		if sid != "" {
			md.Set(SessionTokenName, sid)
		}
		if uid != "" {
			md.Set(UserIDName, uid)
		}
		grpc.SetTrailer(ctx, md)
	}

	return &identity_proto.OAuth2VerifyResp{
		User:    uid,
		Session: sid,
		Error:   "",
	}, nil
}

////////////////////////////////////////////////////////////////
//// PrivateAuthenticationService
////

type PrivateIdentityService struct {
	is *IdentitySvc
}

func (pis *PrivateIdentityService) LoginAs(ctx context.Context, q *identity_proto.LoginAsReq) (*identity_proto.LoginAsResp, error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	log.Println("LoginAs():", q)

	uid := q.User

	sid, err := sess.LoginAs(uid)
	if err != nil {
		return nil, err
	}
	{
		md := make(metadata.MD)
		if sid != "" {
			md.Set(SessionTokenName, sid)
		}
		if uid != "" {
			md.Set(UserIDName, uid)
		}
		grpc.SetTrailer(ctx, md)
	}

	return &identity_proto.LoginAsResp{
		User:    uid,
		Session: sid,
		Error:   "",
	}, nil
}
