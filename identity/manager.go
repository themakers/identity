package identity

import (
	"errors"
	"github.com/themakers/session"
	"time"
)

var (
	ErrSecurityCodeMismatch = errors.New("security code mismatch")
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

// TODO modificate ListIdentities
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
			Identity: i.Info().Identity})
	}
	return idn, ver
}

func (mgr *Manager) Session(token string) *Session {
	sess := &Session{
		manager: mgr,
	}

	if s, err := mgr.sessMgr.Session(token); err != nil {
		panic(err)
	} else {
		// FIXME Make configurable
		if err := s.SetTTL(7 * 24 * time.Hour); err != nil {
			panic(err)
		}

		sess.sess = s
	}

	return sess
}

////////////////////////////////////////////////////////////////
////
////
