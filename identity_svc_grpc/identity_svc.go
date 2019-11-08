package identity_svc_grpc

import (
	"context"
	"errors"
	"fmt"
	"github.com/themakers/identity/cookie"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_svc_grpc/identity_proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
)

// TODO: Should it handle 'app passwords' concept?
// TODO: Support forced verifiers order? (to prevent paid resources overuse)
// TODO: SignIn from SignUp mode if user already exists

//go:generate protoc -I ../identity-proto ../identity-proto/identity.proto --go_out=plugins=grpc:./identity_proto

const (
	SessionTokenName = "session_token"
	UserName         = "user"
)

type IdentitySvc struct {
	cookieCtxKey string
	mgr          *identity.Manager
}

func New(backend identity.Backend, cookieCtxKey string, identities []identity.Identity, verifiers []identity.Verifier) (*IdentitySvc, error) {
	is := &IdentitySvc{
		cookieCtxKey: cookieCtxKey,
	}

	if mgr, err := identity.New(
		backend,
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
	identity_proto.RegisterIdentityPrivateServer(private, &PrivateIdentityService{
		is: is,
	})
}

////////////////////////////////////////////////////////////////
//// Helpers
////

func (is *IdentitySvc) sessionObtain(ctx context.Context) *identity.Session {
	//log.Println("qwertyuiop", ctx.Value(is.cookieCtxKey).(cookie.Cookie).GetSessionID())
	return is.mgr.Session(ctx.Value(is.cookieCtxKey).(cookie.Cookie))
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

func (pis *PublicIdentityService) status(ctx context.Context, sess *identity.Session) (*identity_proto.Status, error) {
	if status, err := sess.CheckStatus(ctx); err != nil {
		return &identity_proto.Status{}, err
	} else {
		return convertStatus(status), nil
	}
}

func (pis *PublicIdentityService) ListSupportedIdentitiesAndVerifiers(ctx context.Context, q *identity_proto.ListSupportedIdentitiesAndVerifiersReq) (response *identity_proto.VerifierDetailsResp, err error) {
	sess := pis.is.sessionObtain(ctx)

	resp := &identity_proto.VerifierDetailsResp{}
	idns, vers, err := sess.ListSupportedIdentitiesAndVerifiers()
	if err != nil {
		return &identity_proto.VerifierDetailsResp{}, err
	}

	for _, idn := range idns {
		resp.IdentitiyNames = append(resp.IdentitiyNames, idn.Name)
	}

	for _, ver := range vers {
		resp.Verifiers = append(resp.Verifiers, &identity_proto.VerifierDetails{
			Name:           ver.Name,
			IdentityName:   ver.IdentityName,
			SupportRegular: ver.SupportRegular,
			SupportReverse: ver.SupportReverse,
			SupportOAuth2:  ver.SupportOAuth2,
			SupportStatic:  ver.SupportStatic,
		})
	}

	return resp, nil
}

func (pis *PublicIdentityService) CheckStatus(ctx context.Context, r *identity_proto.StatusReq) (*identity_proto.Status, error) {
	log.Println("*** CheckStatus ***")
	sess := pis.is.sessionObtain(ctx)

	log.Println("*** CheckStatus ***", fmt.Sprintln(sess.Info()))

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) StartSignIn(ctx context.Context, req *identity_proto.StartSignInReq) (*identity_proto.Status, error) {
	sess := pis.is.sessionObtain(ctx)

	if _, uid := sess.Info();  uid != "" {
		return &identity_proto.Status{}, errors.New("should be unauthenticated")
	}

	if err := sess.StartAuthentication(ctx, identity.ObjectiveSignIn); err != nil {
		return &identity_proto.Status{}, err
	}

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) StartSignUp(ctx context.Context, req *identity_proto.StartSignUpReq) (resp *identity_proto.Status, err error) {
	sess := pis.is.sessionObtain(ctx)

	if _, uid := sess.Info(); uid != "" {
		return &identity_proto.Status{}, errors.New("should be unauthenticated")
	}

	if err := sess.StartAuthentication(ctx, identity.ObjectiveSignUp); err != nil {
		return &identity_proto.Status{}, err
	}

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) StartAttach(ctx context.Context, req *identity_proto.StartAttachReq) (resp *identity_proto.Status, err error) {
	sess := pis.is.sessionObtain(ctx)

	if _, uid := sess.Info(); uid == "" {
		return &identity_proto.Status{}, errors.New("unauthenticated")
	}

	if err := sess.StartAuthentication(ctx, identity.ObjectiveAttach); err != nil {
		return &identity_proto.Status{}, err
	}

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) CancelAuthentication(ctx context.Context, q *identity_proto.CancelAuthenticationReq) (*identity_proto.Status, error) {
	sess := pis.is.sessionObtain(ctx)

	if err := sess.CancelAuthentication(ctx); err != nil {
		return &identity_proto.Status{}, err
	}

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) ListMyIdentitiesAndVerifiers(ctx context.Context, q *identity_proto.ListMyIdentitiesAndVerifiersReq) (response *identity_proto.ListMyIdentitiesAndVerifiersResp, err error) {
	sess := pis.is.sessionObtain(ctx)

	resp := &identity_proto.ListMyIdentitiesAndVerifiersResp{}
	idns, vers, err := sess.ListMyIdentitiesAndVerifiers(ctx)
	if err != nil {
		return &identity_proto.ListMyIdentitiesAndVerifiersResp{}, err
	}

	for _, ver := range vers {
		if ver.Standalone {
			resp.Verifiers = append(resp.Verifiers, ver.Name)
		}
	}
	for _, idn := range idns {
		resp.Identities = append(resp.Identities, &identity_proto.IdentityData{
			Name:     idn.Name,
			Identity: idn.Identity,
		})
	}
	return resp, nil
}

func (pis *PublicIdentityService) Start(ctx context.Context, q *identity_proto.StartReq) (*identity_proto.StartResp, error) {
	sess := pis.is.sessionObtain(ctx)

	for k, v := range q.Values {
		ctx = context.WithValue(ctx, k, v)
	}

	directions, err := sess.Start(ctx, q.VerifierName, q.Args, q.IdentityName, q.Identity)
	if err != nil {
		return &identity_proto.StartResp{}, err
	}

	return &identity_proto.StartResp{
		Directions: directions,
	}, nil
}

func (pis *PublicIdentityService) Verify(ctx context.Context, q *identity_proto.VerifyReq) (*identity_proto.Status, error) {
	sess := pis.is.sessionObtain(ctx)

	verErr := sess.Verify(ctx, q.VerifierName, q.VerificationCode, q.IdentityName, q.Identity)

	stat, err := pis.status(ctx, sess)
	if err != nil {
		return &identity_proto.Status{}, err
	}

	if verErr != nil {
		return stat, status.New(codes.InvalidArgument, verErr.Error()).Err()
	}

	return stat, verErr
}

func (pis *PublicIdentityService) Logout(ctx context.Context, q *identity_proto.LogoutReq) (*identity_proto.Status, error) {
	sess := pis.is.sessionObtain(ctx)

	// TODO Also delete Authentication on logout

	// TODO
	panic("not implemented")

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) UserMerge(ctx context.Context, q *identity_proto.UserMergeReq) (*identity_proto.UserMergeResp, error) {
	//sess := pis.is.sessionObtain(ctx)

	// TODO
	panic("not implemented")

	return nil, nil
}

////////////////////////////////////////////////////////////////
//// PrivateAuthenticationService
////

type PrivateIdentityService struct {
	is *IdentitySvc
}

func (pis *PrivateIdentityService) LoginAs(ctx context.Context, q *identity_proto.LoginAsReq) (*identity_proto.LoginAsResp, error) {
	sess := pis.is.sessionObtain(ctx)

	uid := q.User

	sid, err := sess.LoginAs(uid)
	if err != nil {
		return &identity_proto.LoginAsResp{}, err
	}

	return &identity_proto.LoginAsResp{
		User:    uid,
		Session: sid,
	}, nil
}

////////////////////////////////////////////////////////////////
//// Helpers
////

func convertStatus(status identity.Status) *identity_proto.Status {
	s := &identity_proto.Status{
		Token: status.Token,
	}

	if status.Authenticating != nil {
		au := &identity_proto.StatusAuthenticating{
			RemainingFactors: int64(status.Authenticating.RemainingFactors),
		}
		switch status.Authenticating.Objective {
		case identity.ObjectiveSignIn:
			au.Objective = &identity_proto.StatusAuthenticating_SignIn{SignIn: true}
		case identity.ObjectiveSignUp:
			au.Objective = &identity_proto.StatusAuthenticating_SignUp{SignUp: true}
		case identity.ObjectiveAttach:
			au.Objective = &identity_proto.StatusAuthenticating_Attach{Attach: true}
		default:
			panic("bad objective")
		}
		for _, fact := range status.Authenticating.CompletedFactors {
			au.CompletedFactors = append(au.CompletedFactors, &identity_proto.StatusCompletedFactors{
				VerifierName: fact.VerifierName,
				IdentityName: fact.IdentityName,
				Identity:     fact.Identity,
			})
		}
		s.Authenticating = au
	}

	if status.Authenticated != nil {
		s.Authenticated = &identity_proto.StatusAuthenticated{
			User: status.Authenticated.User,
		}
	}

	return s
}
