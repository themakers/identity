package identity

import (
	"context"
	"golang.org/x/oauth2"
)

////////////////////////////////////////////////////////////////
//// Types
////

type M map[string]string
type B map[string][]byte

type VerifierInfo struct {
	Name         string
	IdentityName string
}

type Verifier interface {
	Info() VerifierInfo
}

type RegularVerifier interface {
	Verifier

	StartRegularVerification(ctx context.Context, identity string, verifierData VerifierData) (securityCode string, err error)
}

type ReverseVerifier interface {
	Verifier

	StartReverseVerification(ctx context.Context) (target, securityCode string, err error)
}

type OAuth2Verifier interface {
	Verifier

	GetOAuth2URL(code string) string
	HandleOAuth2Callback(ctx context.Context, code string) (token *oauth2.Token, err error)
	GetOAuth2Identity(ctx context.Context, accessToken string) (identity *IdentityData, verifierData *VerifierData, err error)
}

type StaticVerifier interface {
	Verifier

	InitStaticVerifier(ctx context.Context, verifierData *VerifierData, args M) (res M, err error)
	StaticVerify(ctx context.Context, verifierData VerifierData, inputCode string) (success bool, err error)
}

////////////////////////////////////////////////////////////////
//// START
////

func (sess *Session) Start(ctx context.Context, verifierName string, args M, identityName, identity string) (M, error) {
	if verifierName == "" {
	}
	auth, err := sess.manager.backend.GetAuthentication(ctx, sess.token)
	if err != nil {
		return nil, err
	}

	ver := sess.manager.verifiers[verifierName]

	idn := sess.manager.identities[identityName]

	switch {
	case ver.SupportRegular, ver.SupportOAuth2:
		idn = ver.Identity
		identityName = idn.Name
	case ver.SupportStatic:
	default:
		panic("shit happened")
	}

	identity, err = idn.Identity.NormalizeAndValidateIdentity(identity)
	if err != nil {
		return nil, err
	}

	var res M

	switch {
	case ver.SupportRegular:
		res, err = sess.regularStart(ctx, ver, auth, args, identityName, identity)
	case ver.SupportOAuth2:
		res, err = sess.oauth2Start(ctx, ver, auth, args, identityName, identity)
	case ver.SupportStatic:
		res, err = sess.staticStart(ctx, ver, auth, args, identityName, identity)
	default:
		panic("shit happened")
	}
	if err != nil {
		return nil, err
	}

	if _, err := sess.manager.backend.SaveAuthentication(ctx, auth); err != nil {
		panic(err)
	}

	return res, nil
}

////////////////////////////////////////////////////////////////
//// VERIFY
////

func (sess *Session) Verify(ctx context.Context, verifierName, verificationCode, identityName, identity string) (bool, error) {
	auth, err := sess.manager.backend.GetAuthentication(ctx, sess.token)
	if err != nil {
		return false, err
	}

	ver := sess.manager.verifiers[verifierName]

	idn := sess.manager.identities[identityName]

	switch {
	case ver.SupportRegular, ver.SupportOAuth2:
		idn = ver.Identity
		identityName = idn.Name
	case ver.SupportStatic:
	default:
		panic("shit happened")
	}

	identity, err = idn.Identity.NormalizeAndValidateIdentity(identity)
	if err != nil {
		return false, err
	}

	var success bool

	switch {
	case ver.SupportRegular:
		success, err = sess.regularVerify(ctx, ver, auth, verificationCode, identityName, identity)
	case ver.SupportOAuth2:
		success, err = sess.oauth2Verify(ctx, ver, auth, verificationCode, identityName, identity)
	case ver.SupportStatic:
		success, err = sess.staticVerify(ctx, ver, auth, verificationCode, identityName, identity)
	default:
		panic("shit happened")
	}
	if err != nil {
		return false, err
	}

	if !success {
		return false, nil
	}

	// FIXME Remove???
	auth, err = sess.manager.backend.SaveAuthentication(ctx, auth)
	if err != nil {
		panic(err)
	}

	if err := sess.handleAuthentication(ctx, auth); err != nil {
		return false, err
	}

	return true, nil
}
