package identity_svc

import (
	"context"
	"fmt"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_svc/identity_proto"
	"github.com/themakers/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//go:generate protoc -I ../identity-proto ../identity-proto/identity.proto --go_out=plugins=grpc:./identity_proto

const (
	UserIDName = "user_id"
)

const SessionTokenName = "session_token"

type IdentitySvc struct {
	mgr *identity.Manager
}

func New(backend identity.Backend, sessMgr *session.Manager, identities []identity.Identity, verifiers []identity.Verifier) (*IdentitySvc, error) {
	is := &IdentitySvc{}

	if mgr, err := identity.New(
		backend,
		sessMgr,
		identities,
		verifiers,
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

func statusError(err error) error {
	return status.Errorf(codes.Internal, "%s", err.Error())
}

////////////////////////////////////////////////////////////////
//// PublicIdentityService
////

type PublicIdentityService struct {
	is *IdentitySvc
}

func (pis *PublicIdentityService) InitializeStaticVerifier(ctx context.Context, req *identity_proto.InitializeStaticVerifierReq) (resp *identity_proto.InitializeStaticVerifierResp, err error) {
	sess := pis.is.mgr.Session(ctx)
	defer sess.Dispose()
	resp = &identity_proto.InitializeStaticVerifierResp{}
	vd := identity.VerifierData{VerifierName: req.VerifierName, AuthenticationData: req.InitializationData, AdditionalData: map[string]string{}}
	_ = sess.InitializeStaticVerifier(ctx, vd.AuthenticationData)
	return resp, nil

}

func (pis *PublicIdentityService) Logout(ctx context.Context, req *identity_proto.LogoutReq) (resp *identity_proto.Status, err error) {
	return
}

func (pis *PublicIdentityService) UserMerge(ctx context.Context, req *identity_proto.UserMergeReq) (resp *identity_proto.UserMergeResp, err error) {
	return
}

func (pis *PublicIdentityService) StartVerification(ctx context.Context, req *identity_proto.StartVerificationReq) (resp *identity_proto.StartVerificationResp, err error) {
	sess := pis.is.mgr.Session(ctx)
	defer sess.Dispose()
	addata := map[string]string{}
	vd := identity.VerifierData{req.VerifierName, req.VerificationData, addata}
	verType := pis.is.mgr.GetVerifierType(req.VerifierName)
	switch verType {
	case "regular":
		aid, err := sess.StartRegularVerification(ctx, req.Identity, vd)
		if err != nil {
			panic(err)
		}
		return &identity_proto.StartVerificationResp{AuthenticationID: aid}, nil
	}
	return &identity_proto.StartVerificationResp{}, nil
}

func (pis *PublicIdentityService) CancelAuthentication(ctx context.Context, req *identity_proto.CancelAuthenticationReq) (resp *identity_proto.Status, err error) {
	return
}

func (pis *PublicIdentityService) StartAuthentication(ctx context.Context, req *identity_proto.StartAuthenticationReq) (resp *identity_proto.StartAuthenticationResp, err error) {
	sess := pis.is.mgr.Session(ctx)
	defer sess.Dispose()

	authres, err := pis.is.mgr.StartAuthentication(ctx, req.VerifierName)
	if err != nil {
		panic(err)
	}
	if authres {

		return &identity_proto.StartAuthenticationResp{AuthenticationSessionExist: true}, nil
	}
	return &identity_proto.StartAuthenticationResp{AuthenticationSessionExist: false}, nil
}

func (pis *PublicIdentityService) ListMyIdentitiesAndVerifiers(ctx context.Context, u *identity_proto.MyVerifiersDetailRequest) (response *identity_proto.VerifierDetailsResponse, err error) {
	resp := &identity_proto.VerifierDetailsResponse{}
	idns, vers := pis.is.mgr.ListMyIdentitiesAndVerifiers(u.Identity)
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
		resp.IdentitiyNames = append(resp.IdentitiyNames, idn.Name)
	}
	return
}

func (pis *PublicIdentityService) ListIdentitiesAndVerifiers(ctx context.Context, q *identity_proto.VerifiersDetailsRequest) (response *identity_proto.VerifierDetailsResponse, err error) {
	sess := pis.is.mgr.Session(ctx)
	defer sess.Dispose()

	resp := &identity_proto.VerifierDetailsResponse{}
	idns, vers := pis.is.mgr.ListAllIndentitiesAndVerifiers()

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
		resp.IdentitiyNames = append(resp.IdentitiyNames, idn.Name)
	}

	return resp, nil
}

func (pis *PublicIdentityService) Verify(ctx context.Context, req *identity_proto.VerifyReq) (resp *identity_proto.VerifyResp, err error) {
	sess := pis.is.mgr.Session(ctx)
	defer sess.Dispose()
	resp = &identity_proto.VerifyResp{}
	verType := pis.is.mgr.GetVerifierType(req.VerifierName)
	switch verType {
	case "regular":
		if err := sess.RegularVerify(ctx, req.AuthenticationID, req.VerificationCode, req.VerifierName, req.Identity); err != nil {
			resp.VerifyStatus = false
		} else {
			resp.VerifyStatus = true
		}
		return resp, nil
	case "oauth2":
		if err := sess.OAuth2Verify(ctx, req.VerifierName, req.VerificationCode); err != nil {
			resp.VerifyStatus = false
			fmt.Println(err)
		} else {
			resp.VerifyStatus = true
		}
		return resp, nil
	}
	// todo: create switch to change verifier type

	return resp, nil
}

func (pis *PublicIdentityService) CheckStatus(ctx context.Context, r *identity_proto.StatusReq) (*identity_proto.Status, error) {
	sess := pis.is.mgr.Session(ctx)
	defer sess.Dispose()
	resp := &identity_proto.Status{}
	authentication, err := sess.CheckStatus(ctx)
	if err != nil {
		panic(err)
	}
	if authentication == 0 {
		resp.Authenticated = true
	} else {
		resp.Authenticated = false
		resp.RemainingFactors = int64(authentication)
	}
	return resp, nil
}

////////////////////////////////////////////////////////////////
//// PrivateAuthenticationService
////

type PrivateAuthenticationService struct {
	auth *IdentitySvc
}
