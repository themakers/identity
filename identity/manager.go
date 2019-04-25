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

func (mgr *Manager) ListMyIdentitiesAndVerifiers(ctx context.Context) (idn []IdentityData, ver []VerifierSummary) {
	token := getIncomingSessionToken(ctx)
	auth, err := mgr.backend.GetAuthenticationBySessionToken(token)
	user, err := mgr.backend.GetUserByID(auth.UserID)
	if err != nil {
		return nil, nil
	}
	for _, uiden := range user.Identities {
		idn = append(idn, IdentityData{Name: uiden.Name,
			Identity: uiden.Identity})
		for _, v := range user.Verifiers {
			ver = append(ver, mgr.ver[v.VerifierName])
		}
	}
	return idn, ver
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
		if err := grpc.SetTrailer(ctx, md); err != nil {
			panic(err)
		}
	}
	return sess
}

func (mgr *Manager) GetVerifierType(vname string) string {
	if mgr.ver[vname].SupportRegular {
		return "regular"
	}
	if mgr.ver[vname].SupportOAuth2 {
		return "oauth2"
	}
	if mgr.ver[vname].SupportStatic {
		return "static"
	}

	return ""
}

////////////////////////////////////////////////////////////////
////
////
