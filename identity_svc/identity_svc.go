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

func statusError(err error) error {
	return status.Errorf(codes.Internal, "%s", err.Error())
}

////////////////////////////////////////////////////////////////
//// PublicIdentityService
////

type PublicIdentityService struct {
	is *IdentitySvc
}

func (pis *PublicIdentityService) ListMyIdentitiesAndVerifiers(ctx context.Context, u *identity_proto.MyVerifiersDetailRequest) (response *identity_proto.VerifierDetailsResponse, err error) {
	resp := &identity_proto.VerifierDetailsResponse{}
	idns, vers := pis.is.mgr.ListMyIdentitiesAndVerifiers(u.Uid)
	for _, ver := range vers {
		resp.Verifiers = append(resp.Verifiers, &identity_proto.VerifierDetails{
			Name:           ver.Name,
			SupportRegular: ver.SupportRegular,
			SupportReverse: ver.SupportReverse,
			SupportOAuth2:  ver.SupportOAuth2,
			SupportStatic:  ver.SupportStatic,
		})
	}
	for _, idn := range idns {
		resp.Identities = append(resp.Identities, idn)
	}

	return

}

func (pis *PublicIdentityService) ListIdentitiesAndVerifiers(ctx context.Context, q *identity_proto.VerifiersDetailsRequest) (response *identity_proto.VerifierDetailsResponse, err error) {
	resp := &identity_proto.VerifierDetailsResponse{}
	idns, vers := pis.is.mgr.ListIndentitiesAndVerifiers()

	for _, ver := range vers {
		resp.Verifiers = append(resp.Verifiers, &identity_proto.VerifierDetails{
			Name:           ver.Name,
			SupportRegular: ver.SupportRegular,
			SupportReverse: ver.SupportReverse,
			SupportOAuth2:  ver.SupportOAuth2,
			SupportStatic:  ver.SupportStatic,
		})
	}
	for _, idn := range idns {
		resp.Identities = append(resp.Identities, idn.Info().Name)
	}

	return resp, nil
}

func (pis *PublicIdentityService) ReverseRequest(ctx context.Context, q *identity_proto.ReverseVerificationReq) (directions *identity_proto.ReverseVerificationDirections, err error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()
	//TODO refactor reverse method
	verificationID, target, securityCode, err := sess.StartType1Verification(ctx, q.Verifier, q.Identity)
	if err != nil {
		return nil, err
	}

	return &identity_proto.ReverseVerificationDirections{
		VerificationID: verificationID,
		Target:         target,
		SecurityCode:   securityCode,
	}, nil
}

func (pis *PublicIdentityService) ReverseResult(ctx context.Context, q *identity_proto.ReverseResultRequest) (resp *identity_proto.ReverseResultResp, err error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()
	//TODO refactor reverse method
	err = sess.AwaitType1Result(ctx, q.VerificationID)
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

	return &identity_proto.ReverseResultResp{
		Session: sid,
		User:    uid,
		Error:   "",
	}, nil
}

func (pis *PublicIdentityService) RegularRequest(ctx context.Context, q *identity_proto.ReqularVerificationReq) (resp *identity_proto.RegularVerificationResp, err error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	verificationID, err := sess.StartType2Verification(ctx, q.Verifier, q.Identity)
	if err != nil {
		return nil, err
	}

	return &identity_proto.RegularVerificationResp{
		VerificationID: verificationID,
	}, nil
}

func (pis *PublicIdentityService) RegularVerify(ctx context.Context, q *identity_proto.RegularVerifyReq) (resp *identity_proto.RegularResultResp, err error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	log.Println("Type2Verify():", q)

	err = sess.Type2Verify(ctx, q.VerificationID, q.SecurityCode)
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
	return &identity_proto.RegularResultResp{
		Session: sid,
		User:    uid,
		Error:   "",
	}, nil
}

func (pis *PublicIdentityService) OAuth2Verify(ctx context.Context, q *identity_proto.OAuth2Req) (*identity_proto.OAuth2VerifyResp, error) {
	sess := pis.is.mgr.Session(GetSessionToken(ctx))
	defer sess.Dispose()

	err := sess.OAuth2Verify(ctx, q.Verifier, q.Code)
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

func (pis *PublicIdentityService) StaticRequest(ctx context.Context, q *identity_proto.StaticVerificationReq) (resp *identity_proto.StaticVerificationResp, err error) {
	return
}

////////////////////////////////////////////////////////////////
//// PrivateAuthenticationService
////

type PrivateAuthenticationService struct {
	auth *IdentitySvc
}
