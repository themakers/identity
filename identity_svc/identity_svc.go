package identity_svc

import (
	"context"
	"errors"
	"github.com/themakers/identity/identity"
	"github.com/themakers/identity/identity_svc/identity_proto"
	"github.com/themakers/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	identity_proto.RegisterIdentityPrivateServer(private, &PrivateIdentityService{
		is: is,
	})
}

////////////////////////////////////////////////////////////////
//// Helpers
////

// TODO: Make private
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

func (is *IdentitySvc) sessionObtain(ctx context.Context) *identity.Session {
	token := GetSessionToken(ctx)
	if token == "" {
		token = session.GenerateRandomToken()
	}

	return is.mgr.Session(token)
}

func sessionDispose(ctx context.Context, sess *identity.Session) {
	token, user, err := sess.Info()
	if err != nil {
		panic(err)
	}

	//token, err := sess.sess.GetID()
	//if err != nil {
	//	panic(err)
	//}

	md := make(metadata.MD)

	md.Set(SessionTokenName, token)

	if user != "" {
		md.Set(UserName, user)
	}

	if err := grpc.SetTrailer(ctx, md); err != nil {
		panic(err)
	}

	sess.Dispose()
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
	defer sessionDispose(ctx, sess)

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
			SupportRegular: ver.SupportRegular,
			SupportReverse: ver.SupportReverse,
			SupportOAuth2:  ver.SupportOAuth2,
			SupportStatic:  ver.SupportStatic,
		})
	}

	return resp, nil
}

func (pis *PublicIdentityService) CheckStatus(ctx context.Context, r *identity_proto.StatusReq) (*identity_proto.Status, error) {
	sess := pis.is.sessionObtain(ctx)
	defer sessionDispose(ctx, sess)

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) StartSignIn(ctx context.Context, req *identity_proto.StartSignInReq) (*identity_proto.Status, error) {
	sess := pis.is.sessionObtain(ctx)
	defer sessionDispose(ctx, sess)

	if _, uid, err := sess.Info(); err != nil {
		return &identity_proto.Status{}, err
	} else if uid != "" {
		return &identity_proto.Status{}, errors.New("should be unauthenticated")
	}

	if err := sess.StartAuthentication(ctx, identity.ObjectiveSignIn); err != nil {
		return &identity_proto.Status{}, err
	}

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) StartSignUp(ctx context.Context, req *identity_proto.StartSignUpReq) (resp *identity_proto.Status, err error) {
	sess := pis.is.sessionObtain(ctx)
	defer sessionDispose(ctx, sess)

	if _, uid, err := sess.Info(); err != nil {
		return &identity_proto.Status{}, err
	} else if uid == "" {
		return &identity_proto.Status{}, errors.New("should be unauthenticated")
	}

	if err := sess.StartAuthentication(ctx, identity.ObjectiveSignUp); err != nil {
		return &identity_proto.Status{}, err
	}

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) StartAttach(ctx context.Context, req *identity_proto.StartAttachReq) (resp *identity_proto.Status, err error) {
	sess := pis.is.sessionObtain(ctx)
	defer sessionDispose(ctx, sess)

	if _, uid, err := sess.Info(); err != nil {
		return &identity_proto.Status{}, err
	} else if uid == "" {
		return &identity_proto.Status{}, errors.New("unauthenticated")
	}

	if err := sess.StartAuthentication(ctx, identity.ObjectiveAttach); err != nil {
		return &identity_proto.Status{}, err
	}

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) CancelAuthentication(ctx context.Context, q *identity_proto.CancelAuthenticationReq) (*identity_proto.Status, error) {
	sess := pis.is.sessionObtain(ctx)
	defer sessionDispose(ctx, sess)

	if err := sess.CancelAuthentication(ctx); err != nil {
		return &identity_proto.Status{}, err
	}

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) ListMyIdentitiesAndVerifiers(ctx context.Context, q *identity_proto.ListMyIdentitiesAndVerifiersReq) (response *identity_proto.VerifierDetailsResp, err error) {
	sess := pis.is.sessionObtain(ctx)
	defer sessionDispose(ctx, sess)

	resp := &identity_proto.VerifierDetailsResp{}
	idns, vers, err := sess.ListMyIdentitiesAndVerifiers(ctx)
	if err != nil {
		return &identity_proto.VerifierDetailsResp{}, err
	}

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

func (pis *PublicIdentityService) Start(ctx context.Context, q *identity_proto.StartReq) (*identity_proto.StartResp, error) {
	sess := pis.is.sessionObtain(ctx)
	defer sessionDispose(ctx, sess)

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
	defer sessionDispose(ctx, sess)

	if _, err := sess.Verify(ctx, q.VerifierName, q.VerificationCode, q.IdentityName, q.Identity); err != nil {
		return &identity_proto.Status{}, err
	}

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) Logout(ctx context.Context, q *identity_proto.LogoutReq) (*identity_proto.Status, error) {
	sess := pis.is.sessionObtain(ctx)
	defer sessionDispose(ctx, sess)

	// TODO Also delete Authentication on logout

	// TODO
	panic("not implemented")

	return pis.status(ctx, sess)
}

func (pis *PublicIdentityService) UserMerge(ctx context.Context, q *identity_proto.UserMergeReq) (*identity_proto.UserMergeResp, error) {
	sess := pis.is.sessionObtain(ctx)
	defer sessionDispose(ctx, sess)

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
	defer sessionDispose(ctx, sess)

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

	switch {
	case status.Authenticating != nil:
		au := &identity_proto.Status_Authenticating{
			Authenticating: &identity_proto.StatusAuthenticating{
				RemainingFactors: int64(status.Authenticating.RemainingFactors),
			},
		}
		switch status.Authenticating.Objective {
		case identity.ObjectiveSignIn:
			au.Authenticating.Objective = &identity_proto.StatusAuthenticating_SignIn{SignIn: true}
		case identity.ObjectiveSignUp:
			au.Authenticating.Objective = &identity_proto.StatusAuthenticating_SignUp{SignUp: true}
		case identity.ObjectiveAttach:
			au.Authenticating.Objective = &identity_proto.StatusAuthenticating_Attach{Attach: true}
		default:
			panic("bad objective")
		}
		for _, fact := range status.Authenticating.CompletedFactors {
			au.Authenticating.CompletedFactors = append(au.Authenticating.CompletedFactors, &identity_proto.StatusCompletedFactors{
				VerifierName: fact.VerifierName,
				IdentityName: fact.IdentityName,
				Identity:     fact.Identity,
			})
		}
	case status.Authenticated != nil:
		s.Status = &identity_proto.Status_Authenticated{
			Authenticated: &identity_proto.StatusAuthenticated{
				User: status.Authenticated.User,
			},
		}
	default:
		s.Status = &identity_proto.Status_Unauthenticated{
			Unauthenticated: true,
		}
	}

	return s
}
