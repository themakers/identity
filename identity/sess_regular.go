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
	_, err = sess.manager.backend.AddTempAuthDataToAuth(AID, map[string]map[string]string{vername: {idn: securitycode}})
	if err != nil {
		panic(err)
	}
	_, err = sess.manager.backend.AddUserToAuthentication(AID, user.ID)
	if err != nil {
		panic(err)
	}

	return AID, err
}

func (sess *Session) RegularVerify(ctx context.Context, AuthenticationID, securityCode, vername, idn string) (err error) {
	// todo make check aid from context and authenticationid as value
	auth, err := sess.manager.backend.GetAuthenticationBySessionToken(AuthenticationID)
	if err != nil {
		panic(err)
	}
	for key, value := range auth.TempAuthenticationData {
		if key == vername {
			for inkey, invalue := range value {
				if inkey == idn && invalue == securityCode {
					data := VerifierData{VerifierName: vername, AuthenticationData: map[string]string{}, AdditionalData: map[string]string{}}
					_, err = sess.manager.backend.AddUserAuthenticationData(auth.UserID, &data)
					err = sess.manager.backend.UpdateFactorStatus(AuthenticationID, vername)
					// todo : update verifier status in authentication
					return nil
				}
			}

		}
	}
	return ErrSecurityCodeMismatch
}
