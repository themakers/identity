package identity

type Options struct {
}

type Manager struct {
	backend Backend

	verifiers  map[string]*VerifierSummary
	identities map[string]*IdentitySummary
}

func New(backend Backend, identities []Identity, verifiers []Verifier) (*Manager, error) {
	mgr := &Manager{
		backend:    backend,
		identities: make(map[string]*IdentitySummary),
		verifiers:  make(map[string]*VerifierSummary),
	}

	for _, ver := range verifiers {
		vs := &VerifierSummary{
			Name:         ver.Info().Name,
			IdentityName: ver.Info().IdentityName,
			Verifier:     ver,
		}
		if vs.IdentityName == "" {
			vs.Standalone = true
		}
		if ver, ok := ver.(RegularVerifier); ok {
			vs.SupportRegular = true
			vs.internal.regularRef = ver
		}
		if ver, ok := ver.(ReverseVerifier); ok {
			vs.SupportReverse = true
			vs.internal.reverseRef = ver
		}
		if ver, ok := ver.(OAuth2Verifier); ok {
			vs.SupportOAuth2 = true
			vs.internal.oauth2Ref = ver

			vs.IdentityName = vs.Name
			identities = append(identities, newIdentityStub(vs.IdentityName))
		}
		if ver, ok := ver.(StaticVerifier); ok {
			vs.SupportStatic = true
			vs.internal.staticRef = ver
		}
		mgr.verifiers[vs.Name] = vs
	}

	for _, idn := range identities {
		is := &IdentitySummary{
			Name:       idn.Info().Name,
			Identity:   idn,
			Standalone: true,
		}

		for _, vs := range mgr.verifiers {
			if vs.IdentityName == is.Name {
				is.Standalone = false
				is.Verifiers = append(is.Verifiers, vs)

				vs.Identity = is
			}
		}

		mgr.identities[is.Name] = is
	}

	return mgr, nil
}

////////////////////////////////////////////////////////////////
////
////

type VerifierSummary struct {
	Name         string
	IdentityName string
	Standalone   bool

	Identity *IdentitySummary

	Verifier Verifier

	SupportRegular bool
	SupportReverse bool
	SupportOAuth2  bool
	SupportStatic  bool
	internal       struct {
		regularRef RegularVerifier
		reverseRef ReverseVerifier
		oauth2Ref  OAuth2Verifier
		staticRef  StaticVerifier
	}
}

type IdentitySummary struct {
	Name       string
	Standalone bool

	Identity Identity

	Verifiers []*VerifierSummary
}
