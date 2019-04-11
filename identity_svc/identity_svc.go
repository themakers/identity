package identity_svc

import (
	"context"
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
	return

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
	vd := []identity.VerifierData{}
	// TODO use session function to start verification
	verType := pis.is.mgr.GetVerifierType(req.VerifierName)

	// todo use switch to choose verification method
	if verType == "regular" {
		aid, err := sess.StartRegularVerification(ctx, req.VerifierName, req.Identity, vd)
		if err != nil {
			panic(err)
		}
		return &identity_proto.StartVerificationResp{AuthenticationID: aid}, nil

	}
	//code, idnn := pis.is.mgr.StartVerification(req.Identity, req.VerifierName, ctx, vd)

	return &identity_proto.StartVerificationResp{}, nil
}

func (pis *PublicIdentityService) CancelAuthentication(ctx context.Context, req *identity_proto.CancelAuthenticationReq) (resp *identity_proto.Status, err error) {
	return
}

func (pis *PublicIdentityService) StartAuthentication(ctx context.Context, req *identity_proto.StartAuthenticationReq) (resp *identity_proto.StartAuthenticationResp, err error) {
	sess := pis.is.mgr.Session(ctx)
	defer sess.Dispose()

	//_ = sess.HandleIncomingIdentity(ctx, &identity.IdentityData{Identity:"mock_identity", Name:"mock_identity"})

	authres, err := pis.is.mgr.StartAuthentication(ctx)
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

	/*sess.

	sessToken := pis.is.mgr.GetSessionToken(ctx)
	if sessToken == "" {
		panic("Empty session")
	}*/
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
	//TODO get session and user
	sess := pis.is.mgr.Session(ctx)
	defer sess.Dispose()
	resp = &identity_proto.VerifyResp{}

	code := pis.is.mgr.GetVerificationCode(ctx, req.VerifierName)
	if code == req.VerificationCode {
		resp.VerifyStatus = true
	} else {
		resp.VerifyStatus = false
	}

	return resp, nil
}

func (pis *PublicIdentityService) CheckStatus(ctx context.Context, r *identity_proto.StatusReq) (*identity_proto.Status, error) {
	// todo finish get status
	sess := pis.is.mgr.Session(ctx)
	defer sess.Dispose()
	resp := &identity_proto.Status{}

	authentication, err := pis.is.mgr.GetStatus(ctx)
	if err != nil {
		panic(err)
	}

	updateFactorsCount := 0
	for _, value := range authentication.FactorsStatus {
		if !value {
			updateFactorsCount++
		}
	}
	authentication.FactorsCount = updateFactorsCount

	if authentication.FactorsCount != 0 {
		resp.Authenticated = true
		resp.Authenticating = false
	} else {
		resp.Authenticating = true
		resp.Authenticated = false
	}

	return resp, nil

}

////////////////////////////////////////////////////////////////
//// PrivateAuthenticationService
////

type PrivateAuthenticationService struct {
	auth *IdentitySvc
}
