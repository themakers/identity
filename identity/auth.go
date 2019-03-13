package identity

import (
	"errors"
	"time"

	"github.com/themakers/session"
)

var (
	ErrSecurityCodeMismatch = errors.New("security code mismatch")
)

type Options struct {
}

type Manager struct {
	backend Backend
	sessMgr *session.Manager

	providers []Provider

	prov map[string]ProviderSummary
}

func New(backend Backend, sessMgr *session.Manager, providers ...Provider) (*Manager, error) {
	mgr := &Manager{
		backend: backend,
		sessMgr: sessMgr,
		prov:    make(map[string]ProviderSummary),
	}

	for _, prov := range providers {
		ps := ProviderSummary{
			Name: prov.Info().Name,
		}
		if prov, ok := prov.(Type1Provider); ok {
			ps.SupportType1 = true
			ps.internal.type1Ref = prov

			// TODO Start worker
		}
		if prov, ok := prov.(RegularProvider); ok {
			ps.SupportType2 = true
			ps.internal.type2Ref = prov
		}
		if prov, ok := prov.(OAuth2Provider); ok {
			ps.SupportOAuth2 = true
			ps.internal.oauth2Ref = prov
		}
		mgr.prov[prov.Info().Name] = ps
	}

	return mgr, nil
}

////////////////////////////////////////////////////////////////
////
////

type ProviderSummary struct {
	Name string

	SupportType1  bool
	SupportType2  bool
	SupportOAuth2 bool

	internal struct {
		type1Ref  Type1Provider
		type2Ref  RegularProvider
		oauth2Ref OAuth2Provider
	}
}

func (mgr *Manager) ListProviders() (prov []ProviderSummary) {
	for _, p := range mgr.providers {
		prov = append(prov, mgr.prov[p.Info().Name])
	}
	return
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
