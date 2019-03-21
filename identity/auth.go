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

func (mgr *Manager) ListMyIdentitiesAndVerifiers(uid string) (idn []string, ver []VerifierSummary) {
	iden, err := mgr.backend.GetUserByID(uid)
	if err != nil {
		return nil, nil
	}
	for _, uiden := range iden.Identities {
		idn = append(idn, uiden.Name)
		for _, v := range mgr.verifiers {
			if uiden.Name == v.Info().IdentityName {
				ver = append(ver, mgr.ver[v.Info().Name])
			}
		}
	}

	return
}

func (mgr *Manager) ListIndentitiesAndVerifiers() (idn []Identity, ver []VerifierSummary) {

	for _, v := range mgr.verifiers {
		ver = append(ver, mgr.ver[v.Info().Name])
	}
	for _, i := range mgr.identities {
		idn = append(idn, mgr.idn[i.Info().Name])
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
