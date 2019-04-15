package identity

import (
	"context"
	"errors"
	"github.com/themakers/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"time"
)

var (
	ErrSecurityCodeMismatch                 = errors.New("security code mismatch")
	ErrAuthenticationForSessionAlreadyExist = errors.New("Authentication for session already exist")
)

type Options struct {
}

type Manager struct {
	backend Backend
	sessMgr *session.Manager

	identities []Identity
	verifiers  []Verifier
	ver        map[string]VerifierSummary
	idn        map[string]Identity
}

func New(backend Backend, sessMgr *session.Manager, identities []Identity, verifiers []Verifier) (*Manager, error) {
	mgr := &Manager{
		backend:    backend,
		sessMgr:    sessMgr,
		identities: identities,
		verifiers:  verifiers,
		idn:        make(map[string]Identity),
		ver:        make(map[string]VerifierSummary),
	}
	for _, ver := range verifiers {
		vs := VerifierSummary{
			Name:         ver.Info().Name,
			IdentityName: ver.Info().IdentityName,
		}
		if ver, ok := ver.(RegularVerification); ok {
			vs.SupportRegular = true
			vs.internal.regularRef = ver
		}
		if ver, ok := ver.(ReverseVerification); ok {
			vs.SupportReverse = true
			vs.internal.reverseRef = ver
		}
		if ver, ok := ver.(OAuth2Verification); ok {
			vs.SupportOAuth2 = true
			vs.internal.oauth2Ref = ver
		}
		if ver, ok := ver.(StaticVerification); ok {
			vs.SupportStatic = true
			vs.internal.staticRef = ver
		}
		mgr.ver[ver.Info().Name] = vs
	}

	for _, idn := range identities {
		mgr.idn[idn.Info().Name] = idn
	}

	return mgr, nil
}

////////////////////////////////////////////////////////////////
////
////

type VerifierSummary struct {
	Name         string
	IdentityName string

	SupportRegular bool
	SupportReverse bool
	SupportOAuth2  bool
	SupportStatic  bool
	internal       struct {
		regularRef RegularVerification
		reverseRef ReverseVerification
		oauth2Ref  OAuth2Verification
		staticRef  StaticVerification
	}
}

func (mgr *Manager) ListMyIdentitiesAndVerifiers(identity string) (idn []IdentityData, ver []VerifierSummary) {
	user, err := mgr.backend.GetUserByIdentity(identity)
	if err != nil {
		return nil, nil
	}
	for _, uiden := range user.Identities {
		idn = append(idn, IdentityData{Name: uiden.Name,
			Identity: uiden.Identity})
		for _, v := range mgr.verifiers {
			if uiden.Name == v.Info().IdentityName {
				ver = append(ver, mgr.ver[v.Info().Name])
			}
		}
	}

	return
}

func (mgr *Manager) ListAllIndentitiesAndVerifiers() (idn []IdentityData, ver []VerifierSummary) {

	for _, v := range mgr.verifiers {
		ver = append(ver, mgr.ver[v.Info().Name])
	}
	for _, i := range mgr.identities {
		idn = append(idn, IdentityData{Name: i.Info().Name,
			Identity: i.Info().Name})
	}
	return idn, ver
}

const SessionTokenName = "session_token"

func getIncomingSessionToken(ctx context.Context) (token string) {
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

func (mgr *Manager) Session(ctx context.Context) *Session {
	sess := &Session{
		manager: mgr,
	}
	if s, err := mgr.sessMgr.Session(getIncomingSessionToken(ctx)); err != nil {
		panic(err)
	} else {
		// FIXME Make configurable
		if err := s.SetTTL(7 * 24 * time.Hour); err != nil {
			panic(err)
		}

		sess.sess = s
	}
	{
		md := make(metadata.MD)
		token, _ := sess.sess.GetID()

		md.Set(SessionTokenName, token)
		//trailer := metadata.Pairs(SessionTokenName, token)
		if err := grpc.SetTrailer(ctx, md); err != nil {
			panic(err)
		}
	}
	return sess
}

func (mgr *Manager) GetStatus(ctx context.Context) (*Authentication, error) {
	token := getIncomingSessionToken(ctx)
	auth, err := mgr.backend.GetAuthenticationBySessionToken(token)
	if err != nil {
		return &Authentication{}, err
	}

	return auth, nil
}

func (mgr *Manager) StartAuthentication(ctx context.Context) (res bool, err error) {
	token := getIncomingSessionToken(ctx)
	_, err = mgr.backend.CreateAuthentication(token)
	if err != nil && err != ErrAuthenticationForSessionAlreadyExist {
		return false, err
	}
	if err == ErrAuthenticationForSessionAlreadyExist {
		return true, nil
	}
	return true, nil
}

func (mgr *Manager) GetVerificationCode(ctx context.Context, vname string) string {
	token := getIncomingSessionToken(ctx)
	auth, err := mgr.backend.GetAuthenticationBySessionToken(token)
	if err != nil {
		panic(err)
	}
	user, err := mgr.backend.GetUserByID(auth.UserID)
	if err != nil {
		panic(err)
	}
	code := ""
	if user == nil {
		code = ""
	} else {
		for _, ver := range user.Verifiers {
			code = ver.AuthenticationData[vname]

		}
	}
	return code

}

//todo add functionality to getvt method

func (mgr *Manager) GetVerifierType(vname string) string {
	if mgr.ver[vname].SupportRegular {
		return "regular"
	}
	return ""
}

////////////////////////////////////////////////////////////////
////
////
