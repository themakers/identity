package identity

import (
	"context"
	"google.golang.org/grpc/metadata"
	"log"
)

func (sess *Session) StartRegularVerification(ctx context.Context, vername, idn string, vd []VerifierData) (AuthenticationID string, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		panic(ok)
	}
	AID := md[SessionTokenName][0]
	p := sess.manager.ver[vername].internal.regularRef
	log.Println("Regular VERIFIER", sess.manager.ver[vername], p, p.Info().Name)

	idn, err = sess.manager.idn[p.Info().IdentityName].NormalizeAndValidateData(idn)

	_ = sess.handleIncomingIdentity(ctx, &IdentityData{Identity: idn, Name: p.Info().IdentityName})
	user, err := sess.manager.backend.GetUserByIdentity(idn)
	if err != nil {
		panic(err)
	}
	securitycode, err := p.StartRegularVerification(ctx, idn, vd)
	if err != nil {
		panic(err)
	}
	data := VerifierData{AuthenticationData: map[string]string{idn: securitycode}, AdditionalData: map[string]string{}}
	_, err = sess.manager.backend.AddUserAuthenticationData(user.ID, &data)
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddUserToAuthentication(AID, user.ID)
	if err != nil {
		panic(err)
	}

	return AID, err
}

func (sess *Session) RegularVerify(ctx context.Context, AuthenticationID, securityCode, idn string) (err error) {
	auth, err := sess.manager.backend.GetAuthenticationBySessionToken(AuthenticationID)
	if err != nil {
		panic(err)
	}
	user, err := sess.manager.backend.GetUserByID(auth.UserID)
	//todo update choosing storedcode
	dem := user.Verifiers[0].AuthenticationData[idn]
	// todo update authentication in storage with success verification
	if dem == securityCode {
		return nil
	} else {
		return ErrSecurityCodeMismatch
	}
}
